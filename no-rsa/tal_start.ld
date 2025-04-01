OUTPUT_FORMAT(binary)
ENTRY(displace_func)
SECTIONS
{
	. = 0x10020980;
	.text :
	{
		*(.text)
	}
	.data :
	{
		*(.data)
		*(.rodata)
	}
}
