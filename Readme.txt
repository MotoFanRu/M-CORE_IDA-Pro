MCORE M210/210S Processor Module

Known to work on IDA 4.7
w/ recompile I'd imagine it'd work on other versions.

-------------------------------------
TO INSTALL

Copy Release\mcore.w32 %IDADIR%\procs

-------------------------------------
TO BUILD

Open up mcore.sln in VS.NET and `Build'

-------------------------------------
TO RE-GENERATE OPCODE TABLE

Use the gennodes.py script in linux_opmap_parsing, along with mcore-optab
Hand-tweak any bugs and merge into the relevant .cpp file

-------------------------------------
FLIRT SIGNATURES

I generated flirt signatures against the default freescale GNU C library.
This is impossible with custom processor types, so I told flirt I was
generating ARM signatures and then hexedited the signature file to force it
as "MCORE"

-------------------------------------
TO DO

This is a processor module, not a file format module.  The analysis is very
basic, doesn't do stack variable propagation, has little capability to do
register call tracing, and so on.

