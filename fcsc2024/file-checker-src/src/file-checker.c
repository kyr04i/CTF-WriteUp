/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

static char *files[5];

__attribute__((nonnull, access(write_only, 1)))
static bool getInt(size_t *n)
{
	return 1 == scanf("%lu", n);
}

__attribute__((nonnull, access(write_only, 1)))
static bool getIndex(size_t *n)
{
	const size_t count = sizeof(files) / sizeof(*files);

	size_t index;

	printf("index: ");
	if(!getInt(&index)) {
		fprintf(stderr, "Could not read index\n");
		return false;
	}

	if(index >= count) {
		fprintf(stderr, "Index out of bounds\n");
		return false;
	}

	*n = index;
	return true;
}

static void menu(void)
{
	puts("1. prepare a file");
	puts("2. clean a file");
	puts("3. handle a file");
	puts("4. leave");
	printf("> ");
}

static void prepare(void)
{
	size_t index;
	if(!getIndex(&index))
		return;

	size_t size;
	printf("size: ");
	if(!getInt(&size)) {  // arbitrary size
 		fprintf(stderr, "Could not read size\n");
		return;
	}

	char *buffer = malloc(size + 1);
	if(NULL == buffer) {
		perror("malloc");
		return;
	}

	memset(buffer, 0, size + 1);

	// drop the newline
	fgetc(stdin);

	printf("file name: ");
	if(NULL == fgets(buffer, size + 1, stdin)) {
		perror("fgets");
		free(buffer);
		return;
	}

	buffer[strcspn(buffer, "\n")] = 0;
	files[index] = buffer;
}

static void clean(void)
{
	size_t index;
	if(!getIndex(&index))
		return;

	free(files[index]);
}

static void handle(void)
{
	size_t index;
	if(!getIndex(&index))
		return;

	static const char *const modes[] = {
		"r",
		"r+",
		"a"
	};

	printf("Mode:\n");
	//for(size_t i = 0; i < sizeof(modes) / sizeof(*modes); i++)
	//	printf("%lu: %s\n", i, modes[i]);
	puts("1. read-only");
	puts("2. read + write");
	puts("3. read + write + create + append"); // useful for dirs

	size_t mode;
	if(!getInt(&mode))
		return;

	// Open the file with the specified mode
	FILE *fp = fopen(files[index], modes[mode - 1]);
	if(NULL == fp)
		return perror("fopen");

	if(0 != fclose(fp))
		return perror("fclose");

	puts("Permission check passed!");
}

int main(void)
{
	// Ubuntu's libc is not relro
	// Baddies use that to hijack pointers to e.g. strlen *in the libc*
	// So we add an additional layer of protection here
	if(NULL == getenv("LD_BIND_NOW")) {
		fprintf(stderr, "LD_BIND_NOW is not set!\n");
		return EXIT_FAILURE;
	}

	setbuf(stdout, NULL);

	while(1) {
		menu();

		size_t choice;
		if(!getInt(&choice)) {
			fprintf(stderr, "Error: could not read integer\n");
			return EXIT_FAILURE;
		}
		choice--;

		static void (*const f[])(void) = {
			prepare,
			clean,
			handle,
		};
		const size_t count = sizeof(f) / sizeof(*f);

		if(count == choice)
			return EXIT_SUCCESS;

		if(choice < count)
			f[choice]();
	}
}
