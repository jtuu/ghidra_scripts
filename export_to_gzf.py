from java.io import File

prog = getCurrentProgram()
df = prog.getDomainFile()
outfile = File("output.gzf")
end(True)
df.packFile(outfile, monitor)
