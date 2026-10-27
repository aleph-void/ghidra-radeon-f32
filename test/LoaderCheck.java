// Checks what the Radeon F32 firmware loader did with a synthetic image.
// Script args: <outfile> <expected language id> <expected table entries (0 = no btab block)> <expected code bytes>
//@category Testing

import java.io.PrintStream;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

public class LoaderCheck extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		PrintStream out = new PrintStream(a[0]);
		StringBuilder err = new StringBuilder();
		if (!currentProgram.getLanguageID().getIdAsString().equals(a[1])) {
			err.append(" language ").append(currentProgram.getLanguageID());
		}
		if (!currentProgram.getExecutableFormat().equals("AMD Radeon F32 microcode")) {
			err.append(" loader ").append(currentProgram.getExecutableFormat());
		}
		int codeBytes = Integer.parseInt(a[3]);
		MemoryBlock code = currentProgram.getMemory().getBlock("code");
		if (code == null || code.getSize() != codeBytes || !code.isExecute()) {
			err.append(" code block ").append(code);
		}
		int entries = Integer.parseInt(a[2]);
		MemoryBlock tab = currentProgram.getMemory().getBlock("btab");
		if ((tab == null) != (entries == 0) || (tab != null && tab.getSize() != entries * 4L)) {
			err.append(" btab block ").append(tab);
		}
		int insns = 0;
		var it = currentProgram.getListing().getInstructions(true);
		while (it.hasNext()) {
			it.next();
			insns++;
		}
		if (insns != codeBytes / 4) {
			err.append(" instructions ").append(insns).append(" (want ").append(codeBytes / 4).append(")");
		}
		if (entries > 0) {
			Address h = currentProgram.getAddressFactory().getAddressSpace("IM").getAddress(8 * 4);
			boolean found = false;
			for (Symbol s : currentProgram.getSymbolTable().getSymbols(h)) {
				found |= s.getName().equals("PKT_0x10") || s.getName().equals("PKT_0x11");
			}
			if (!found) {
				err.append(" no PKT_ label at instruction 8, symbols there:");
				for (Symbol s : currentProgram.getSymbolTable().getSymbols(h)) {
					err.append(" ").append(s.getName());
				}
				var si = currentProgram.getSymbolTable().getAllSymbols(true);
				int k = 0;
				while (si.hasNext() && k++ < 8) {
					err.append(" [").append(si.next().getName()).append("]");
				}
			}
		}
		out.println(err.length() == 0 ? "OK" : "FAIL" + err);
		out.close();
	}
}
