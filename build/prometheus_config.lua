return {
 LuaVersion="LuaU", NameGenerator="MangledShuffled", PrettyPrint=false, Seed=0,
 Steps={
  { Name = "Vmify", Settings = {} },
  { Name = "EncryptStrings", Settings = {} },
  { Name = "Cff", Settings = {} },
  { Name = "ConstantArray", Settings = { Threshold = 1, StringsOnly = true, Shuffle = true, Rotate = true, LocalWrapperThreshold = 0 } },
  { Name = "WrapInFunction", Settings = {} }
 }
}
