/* Apache License 2.0 (see LICENSE.txt).  Ghidra-Rare addition to the Radeon F32 module. */
package radeonf32;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.program.model.address.AddressSet;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for AMD Radeon command-processor microcode images (PFP, ME, CE, MEC, RLC firmware).
 *
 * Two layouts exist.  The old one is the bare image: big-endian instruction words, code padded to a
 * multiple of 4 KB, then (for the packet-processing engines) a jump table at the very end.  The new
 * one starts with a 0x100-byte header (size, header size, ..., ucode size, ucode offset, CRC) followed
 * by the same image with little-endian words.  The jump table has one dword per PM4 packet type:
 * packet number in the upper 16 bits, instruction word number of its handler in the lower 16 bits;
 * the processor's {@code btab} instruction dispatches through it.  The loader maps the code at IM:0,
 * keeps the table in its own block and labels every handler.
 */
public class F32FirmwareLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "AMD Radeon F32 microcode";
	static final String LANG_BE = "F32:BE:64:default";
	static final String LANG_LE = "F32:LE:64:default";
	static final int HEADER = 0x100;
	static final long MAX_IMAGE = 0x40000;

	/** Parsed layout of an image; null if the bytes do not look like F32 microcode. */
	record Layout(boolean little, int codeOffset, int codeSize, int tableSize) {
	}

	static Layout analyze(byte[] b) {
		ByteBuffer le = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
		if (b.length > HEADER + 0x100 && le.getInt(0) == b.length && le.getInt(24) == HEADER &&
			(long) le.getInt(20) + HEADER == b.length) {
			return body(b, true, HEADER);
		}
		return body(b, false, 0);
	}

	static boolean validOpcode(int op) {
		return op <= 0x2 || (op >= 0x4 && op <= 0xb) || (op >= 0xc && op <= 0x12) ||
			(op >= 0x14 && op <= 0x1f) || (op >= 0x20 && op <= 0x26) || (op >= 0x30 && op <= 0x37);
	}

	private static Layout body(byte[] b, boolean little, int off) {
		int n = b.length - off;
		if (n < 0x1000 || n % 4 != 0 || n > MAX_IMAGE) {
			return null;
		}
		int code = n & ~0xfff;
		int table = n - code;
		ByteBuffer buf = ByteBuffer.wrap(b).order(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
		for (int i = code; i < n; i += 4) {
			int w = buf.getInt(off + i);
			int target = w & 0xffff;
			int packet = w >>> 16;
			if (packet > 0xff || target * 4 >= code) {
				return null;
			}
		}
		if (table == 0 && !little) {
			// a bare image without a jump table has no signature at all: require that nearly every word has
			// one of the opcodes the processor defines (random data hits about half of them)
			int ok = 0;
			for (int i = 0; i < code; i += 4) {
				if (validOpcode(buf.getInt(off + i) >>> 26)) {
					ok++;
				}
			}
			if (ok * 100L < (code / 4) * 97L) {
				return null;
			}
		}
		return new Layout(little, off, code, table);
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 60;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() > MAX_IMAGE + HEADER) {
			return specs;
		}
		Layout l = analyze(provider.getInputStream(0).readAllBytes());
		if (l != null) {
			specs.add(new LoadSpec(this, 0,
				new LanguageCompilerSpecPair(l.little ? LANG_LE : LANG_BE, "default"), true));
		}
		return specs;
	}

	@Override
	protected void load(Program program, Loader.ImporterSettings settings)
			throws CancelledException, IOException {
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();
		byte[] all = settings.provider().getInputStream(0).readAllBytes();
		Layout l = analyze(all);
		if (l == null) {
			throw new IOException("not an F32 microcode image");
		}
		AddressSpace im = program.getAddressFactory().getAddressSpace("IM");
		try {
			MemoryBlock code = MemoryBlockUtils.createInitializedBlock(program, false, "code",
				im.getAddress(0), new ByteArrayInputStream(all, l.codeOffset, l.codeSize), l.codeSize,
				"Microcode", NAME, true, false, true, log, monitor);
			// The whole code area is instructions (fixed 4-byte words, computed jumps through tables in the
			// code): disassemble it linearly instead of following flow, which stops at every `b rN` / `btab`.
			AddressSet codeSet = new AddressSet(code.getStart(), code.getEnd());
			new DisassembleCommand(codeSet, codeSet, false).applyTo(program, monitor);
			SymbolTable st = program.getSymbolTable();
			st.createLabel(im.getAddress(0), "Reset", SourceType.IMPORTED);
			st.addExternalEntryPoint(im.getAddress(0));
			if (l.tableSize > 0) {
				Address tab = im.getAddress(l.codeSize);
				MemoryBlockUtils.createInitializedBlock(program, false, "btab", tab,
					new ByteArrayInputStream(all, l.codeOffset + l.codeSize, l.tableSize), l.tableSize,
					"Packet jump table: packet number << 16 | handler instruction number", NAME, true,
					false, false, log, monitor);
				ByteBuffer buf = ByteBuffer.wrap(all, l.codeOffset + l.codeSize, l.tableSize).slice()
						.order(l.little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
				for (int i = 0; i < l.tableSize; i += 4) {
					int w = buf.getInt(i);
					Address h = im.getAddress((w & 0xffff) * 4L);
					String name = String.format("PKT_0x%x", w >>> 16);
					try {
						st.createLabel(h, name, SourceType.IMPORTED);
						st.addExternalEntryPoint(h);
					}
					catch (Exception e) {
						log.appendMsg(NAME, name + ": " + e.getMessage());
					}
				}
			}
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}
}
