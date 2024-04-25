#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

bool ENEMY_CHEATING = false;
bool US_CHEATING = false;

void read_flage() {
	// Read in flage
	char flage[64] = {0};
	FILE *f = fopen("flag.txt", "r");	
	if (f == NULL) {
		printf("Error reading flag file\n");
		exit(1);
	}

	// Store flage
	fscanf(f, "%s", flage);

	// Print flage
	printf("Wow, you went against a cheater AND you shut them out?? Pew pew! You have the clutch gene: %s\n", flage);
}

typedef struct game_t {
	char msg[0x64];
	int enemy_team;
	int our_team;
	int last_used_weapon;
} game;

typedef struct round_node_t {
	char msg[0x64];
	int cheater_detected;
	int round_num;
} round_node;

round_node **rounds;
int num_rounds = 7;

void get_message(char *msg, int len) {
	printf("Okay, what message would you like to leave?\n");
	fgets(msg, len, stdin);
}

int filter_message(char *msg, int gun_choice) {
	// Cheater filter
	if (strstr(msg, "cheater") != NULL) {
		return 1;
	}

	// Swear filter (no swearing in my good wholesome fps)
	// Certain types of players tend to curse more than others smh
	if (gun_choice == 3 && strstr(msg, "heck") != NULL) {
		printf("Swear detected! Filtering out\n");
		int idx = strstr(msg, "heck") - msg;
		int after_len = strlen(msg) + 1 - idx; 
		char *before = malloc(idx + 1);
		char *after = malloc(after_len);
		strncpy(after, msg+idx+4, after_len);
		strncpy(msg + idx, "*****", 5);
		strncpy(msg+idx+5, after, after_len);
		msg[idx+5+after_len] = '\0';

		free(before);
		free(after);
		return 2;	
	}

	return 0;
}

game* play_rounds() {
	char *weapons[] = {"CLAH-SICK", "STINGAR", "VONDAL", "PHANTOOM", "AHH-P"};
	int num_weapons = 5;
	game* score = malloc(sizeof(game));
	score->enemy_team = 0;
	score->our_team = 0;

	// Init rounds
	rounds = malloc(sizeof(round_node*) * num_rounds);
	for (int i = 0; i < num_rounds; i++) {
		rounds[i] = malloc(sizeof(round_node));
	}

	// Print all weapons
	printf("Here are the possible weapon choices: \n");
	for (int i = 0; i < num_weapons; i++) {
		printf("%d: %s\n", i, weapons[i]);
	}
	printf("\n");

	int curr_round = 0;
	while (true) {
		puts("Choose your weapon: ");
		int gun_choice = -1;
		scanf("%d", &gun_choice);

		if (gun_choice < 0 || gun_choice >= num_weapons) {
			printf("Invalid choice, try again");
			continue;
		}
		
		printf("Alright, so you chose %s\n", weapons[gun_choice]); 

		printf("\n*pew pew*\n\n");

		if (curr_round % 2 == 0) {
			score->our_team += 1;
			printf("Congrats on the round win!!\n");
		}
		else {
			score->enemy_team += 1;
			printf("Aww, you lost. You'll get em next time\n");
		}
		
		printf("Would you like to send a post-round message? (y/n): ");
		char choice = '\0';
		char newline = '\0';
		scanf(" %c", &choice);
		scanf("%c", &newline); 
		if (choice == 'y') {
			get_message(rounds[curr_round]->msg, 0x64);
			int ret = filter_message(rounds[curr_round]->msg, gun_choice);
			
			if (ret == 1) {
				rounds[curr_round]->cheater_detected = 1;
			}
		}
		
		if (rounds[curr_round]->cheater_detected == 1) {
			printf("Huh, so there's a cheater? I'm going to pretend like I never saw that and just forget that round existed\n");
			rounds[curr_round]->cheater_detected = 0;
			free(rounds[curr_round]);
			printf("Would you like to report this to the devs? ");
			char choice = '\0';
			char newline = '\0';
			scanf(" %c", &choice);
			scanf("%c", &newline);
			fflush(0);
			if (choice == 'y') {
				char *msg = malloc(0x70);
				get_message(msg, 0x70);
				printf("Thanks for filing your report! We'll take care of this as soon as possible (by that, I mean in 293753298 business days)\n");
			}
		}

		// Now update the game state
		curr_round += 1;
		score->last_used_weapon = gun_choice;
		if (curr_round == num_rounds) break;
	}

	return score;
}

bool cheater_checker() {
	for (int i = 0; i < num_rounds; i++) {
		if (rounds[i]->cheater_detected == 1) return true;
	}
	
	return false;
}

int play_pew_pew_game() {
	printf("Welcome to the completely original and not a rip-off Pew Pew Game :tm:! So glad you're here!\n");
	printf("Get ready for a super fun and totally not toxic game :)\n");

	game *res = play_rounds();

	puts("Thanks for playing! Hope you had fun :)");
	puts("Would you like to leave a comment about the game so we can improve it for future spin-offs? ");

	char choice = '\0';
	char newline = '\0';
	scanf(" %c", &choice);
	scanf("%c", &newline);
	fflush(0);
	if (choice == 'y') {
		get_message(res->msg, 0x64);
		filter_message(res->msg, res->last_used_weapon);
	}

	bool is_cheater = cheater_checker();

	if (is_cheater) {
		if (res->enemy_team == 0) {
			return 0; // 0
		}
		else {
			puts("Dang, you're dogwater. Go back to the range");
			return 1;
		}
	}
	else {
		puts("Not good enough. Should be able to take out cheaters as well\n");
	}
	
	return 1;
}

int main() {
	int ret = play_pew_pew_game();

	if (ret == 0) {
		read_flage();
	}

	return 0;
}
