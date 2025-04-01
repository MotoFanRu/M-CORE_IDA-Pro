/*
 * EXL, 31-Mar-2025
 * fkcoder, 31-Mar-2025
 *
 * MotoFan.Ru / MOTODEV
 *
 * # Compile patch:
 *  mcore-elf-gcc -nostdinc -nostdlib -fshort-wchar -funsigned-char -fpic -fpie -mbig-endian -m340 -O2 -DFTR_A835 -c tal_start.c -o tal_start.o
 *
 * # Create binary:
 *  mcore-elf-ld -nostdinc -nostdlib -Bstatic tal_start.o -T tal_start.ld -o patch.bin
 *
 * # Change opcode 0D 27 to 0D F7 to compare with r15 not r2:
 *  python -c "with open('patch.bin', 'r+b') as f: data = f.read(); f.seek(0); f.write(data.replace(b'\x0D\x27', b'\x0D\xF7'))"
 */

#if defined(FTR_A835)
	#define start_phone ((void (*)(void)) 0x10020F6C)
	#define important_func ((void (*)(void)) 0x10022FB4)
#elif defined(FTR_A845)
	#define start_phone ((void (*)(void)) 0x10020F74)
	#define important_func ((void (*)(void)) 0x10022FE8)
#else
	#error "Unknown phone!"
#endif

extern void displace_func(int r2) {
	if (r2 < 0x10020000) {
		start_phone();
	} else {
		important_func();
	}
}
