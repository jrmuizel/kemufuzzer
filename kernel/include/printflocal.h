#define	ALT		0x001		/* alternate form */
#define	LADJUST		0x004		/* left adjustment */
#define	LONGDBL		0x008		/* long double */
#define	LONGINT		0x010		/* long integer */
#define	LLONGINT	0x020		/* long long integer */
#define	SHORTINT	0x040		/* short integer */
#define	ZEROPAD		0x080		/* zero (as opposed to blank) pad */
#define	FPT		0x100		/* Floating point number */
#define	GROUPING	0x200		/* use grouping ("'" flag) */
					/* C99 additional size modifiers: */
#define	SIZET		0x400		/* size_t */
#define	PTRDIFFT	0x800		/* ptrdiff_t */
#define	INTMAXT		0x1000		/* intmax_t */
#define	CHARINT		0x2000		/* print char using int format */

/*
 * Macros for converting digits to letters and vice versa
 */
#define	to_digit(c)	((c) - '0')
#define is_digit(c)	((unsigned)to_digit(c) <= 9)
#define	to_char(n)	((n) + '0')

/* Size of the static argument table. */
#define STATIC_ARG_TBL_SIZE 8

union arg {
  int32_t	intarg;
  uint32_t	uintarg;
  int32_t	longarg;
  uint32_t	ulongarg;
  int64_t longlongarg;
  uint64_t ulonglongarg;
  int32_t ptrdiffarg;
  uint32_t	sizearg;
  int64_t intmaxarg;
  uint64_t uintmaxarg;
  void	*pvoidarg;
  int8_t	*pchararg;
  int8_t *pschararg;
  int16_t	*pshortarg;
  int32_t	*pintarg;
  int32_t	*plongarg;
  int64_t *plonglongarg;
  int32_t *pptrdiffarg;
  uint32_t	*psizearg;
  int64_t *pintmaxarg;
};

/* Handle positional parameters. */
int	__find_arguments(const char *, va_list, union arg **);
