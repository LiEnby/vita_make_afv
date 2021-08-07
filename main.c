#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


typedef struct act_file{
	uint32_t magic_number;
	uint32_t version;
	uint32_t issue_number;
	uint32_t start_time;
	uint32_t end_time;
	uint8_t activation_key[0x10];
	uint8_t reserved[0x1C];
	uint8_t activation_token_enc[0x40];
} act_file;

void bin2hex(char* src, char* dst, int size){
	char *ptr = &dst[0];
	for(int i = 0; i < size; i++){
		ptr += sprintf(ptr, "%02X", (uint8_t)src[i]);
	}
}

int main(int argc, char *argv[]){
	char* output_filename;

	if(argc < 3){
		printf("Usage: <act.dat> <actsig.dat> [vita_actvation.afv]");
	}
	else{
		// Optional output filename
		if(argc > 3){ 

			int fileNameSz = strlen(argv[3])+5;
			output_filename = (char*)malloc(fileNameSz);
			memset(output_filename, 0x00, fileNameSz);
			strncpy(output_filename, argv[3], fileNameSz);
		}
		else{
			int fileNameSz = 0x20;
			output_filename = (char*)malloc(fileNameSz);
			memset(output_filename, 0x00, fileNameSz);
			strncpy(output_filename, "vita_actvation.afv", fileNameSz);
		}
		
		FILE* afvFd = fopen(output_filename, "wb");
		FILE* actFd = fopen(argv[1], "rb");
		FILE* actSigFd = fopen(argv[2], "rb");
		
		
		// Error Handling
		if(afvFd == NULL){
			perror("Failed to open afv for writing: ");
			return 1;
		}
		
		if(actFd == NULL){
			perror("Failed to open act.dat for reading: ");
			return 2;
		}
		
		if(actSigFd == NULL){
			perror("Failed to open actsig.dat for reading: ");
			return 3;
		}


		
		// Read act.dat File
		act_file actDat;
		fread(&actDat, sizeof(act_file), 1,actFd);
		fclose(actFd);

		// Read actSig.dat file;
		char activation_signature[0x100];
		fread(activation_signature, 0x100, 1, actSigFd);
		fclose(actSigFd);

		// Get activation key
		char activation_key_hex[0x500];
		char activation_token_enc_hex[0x500];
		char activation_signature_hex[0x500];
		
		memset(activation_key_hex, 0x00, 0x500);
		memset(activation_token_enc_hex, 0x00, 0x500);
		memset(activation_signature_hex, 0x00, 0x500);
		bin2hex(actDat.activation_key, activation_key_hex, 0x10);
		bin2hex(actDat.activation_token_enc, activation_token_enc_hex, 0x40);
		bin2hex(activation_signature, activation_signature_hex, 0x100);
		
		

		if(actDat.magic_number == 0x746361 && actDat.version == 1){
					
			// Basically, we do a data dump now
			printf("Magic Number: 0x%x\n", actDat.magic_number);
			printf("Version Number: %u\n", actDat.version);
			printf("Issue Number: %u\n", actDat.issue_number);
			
			printf("Activation Start Date: %u\n", actDat.start_time);
			printf("Activation End Date: %u\n", actDat.end_time);
			
			printf("Activation Key: %s\n", activation_key_hex);
			printf("Activation Token: %s\n", activation_token_enc_hex);
			printf("Activation Signature: %s\n", activation_signature_hex);
			
			char line1[0x80000];
			char line2[0x80000];
			
			printf("\n\nGenerating AFV....\n\n");
			
			snprintf(line1, 0x80000-1, "%s, %u, %u,         %u, %s\n",activation_key_hex, actDat.start_time, actDat.end_time, actDat.issue_number, activation_token_enc_hex);
			snprintf(line2, 0x80000-1, "%s\n",activation_signature_hex);
			
			// Generate AFV
			fprintf(afvFd, "# VITA/ActivationCode\n");
			printf("# VITA/ActivationCode\n");
			fprintf(afvFd, "# format_version=1\n");
			printf("# format_version=1\n");
			fprintf(afvFd, "# code_num=1\n");
			printf("# code_num=1\n");
			
			fprintf(afvFd, "# code_size=%u\n", strlen(line1));
			printf("# code_size=%u\n", strlen(line1));
			fprintf(afvFd, "# extra_data_size=%u\n", strlen(line2));
			printf("# extra_data_size=%u\n", strlen(line2));
			
			fprintf(afvFd, "%s", line1);
			printf("%s", line1);
			fprintf(afvFd, "%s", line2);
			printf("%s", line2);
		}
		else{
			fprintf(stderr, "Invalid magic number 0x%x",actDat.magic_number);
			return 4;
		}
		printf("All Done!\n");
		return 0;
	}
	
}