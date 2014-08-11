using BeaEngineCS;
using System;
using System.IO;

namespace Tests
{
  internal class Program
  {
    public static void Main(string[] args)
    {
      //string file = "Tests.exe";
      //string file = "BeaEngine.dll";
      string file = "BeaEngine64.dll";
      if (args.Length > 0)
        file = args[0];
      byte[] bytes = File.ReadAllBytes(file);
      doStuff(ref bytes);
      Console.ReadKey();
    }

    private static void doStuff(ref byte[] bytes)
    {
      uint[] rva = masker.GetRVA(ref bytes);
      if (rva.Length < 1)
        return;
      int[] locs = masker.GetAddressMaskLocs(ref bytes, rva);

      UnmanagedBuffer buffer = new UnmanagedBuffer(ref bytes);
      BeaEngine._Disasm disasm = new BeaEngine._Disasm();
      ulong begin = (ulong)buffer.Ptr.ToInt64();
      disasm.InstructionPointer = (UIntPtr)(begin + rva[0]);
      disasm.Options |= BeaEngine.SpecialInfo.NasmSyntax;
      ulong loc;
      int result;
      string bytesStr;

      for (int counter = 0; counter < 100; counter++) // First 100 lines of disassembly code.
      {
        result = BeaEngine.Disassemble(ref disasm);
        if (result == BeaEngine.UnknownOpcode || result == BeaEngine.OutOfBlock)
          break;
        loc = disasm.InstructionPointer.ToUInt64() - begin;
        bytesStr = "";
        for (int i = 0; i < result; i++)
          bytesStr += (Array.IndexOf<int>(locs, (int)loc + i) < 0) ? bytes[loc + (ulong)i].ToString("X2") + " " : "?? ";
        Console.WriteLine(string.Format("0x{0,-6:X} {1,-30} {2}", loc, bytesStr.Trim(), disasm.CompleteInstr));
        disasm.InstructionPointer = (UIntPtr)(disasm.InstructionPointer.ToUInt64() + (ulong)result);
      }
    }
  }
}