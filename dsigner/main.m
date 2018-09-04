//
//  main.m
//  dsigner
//
//  Created by Derek Selander on 9/3/18.
//  Copyright © 2018 Razeware. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <getopt.h>
#import <libgen.h>
@import MachO;
@import Foundation;
@import Cocoa;


struct linkedit_data_command * codesign_offset(char *buffer) {
  
  // Get the Mach-O header's memory address of UIKit or UIKitCore
  struct mach_header_64* header = (struct mach_header_64*)buffer;
  assert(header->magic == MH_MAGIC_64);
  
  
  uintptr_t cur_pointer = (uintptr_t)header + sizeof(struct mach_header_64);
  
  // LC_SEGMENT_64 for __LINKEDIT
  struct segment_command_64 *linkedit_cmd = NULL;

  // LC_CODE_SIGNATURE for __LINKEDIT
  struct linkedit_data_command *linkedit_code_signature = NULL;
  
  
  // Get the LC_SYMTAB Load Command and linkedit section Load Command
  for (int i = 0; i < header->ncmds; i++) {
    struct load_command *cur_cmd =  (struct load_command *)cur_pointer;
    
    if (cur_cmd->cmd == LC_CODE_SIGNATURE) {
      linkedit_code_signature = (struct linkedit_data_command *)cur_cmd;
    }
    
    // LC_SEGMENT_64
    if (cur_cmd->cmd == LC_SEGMENT_64) {
      struct segment_command_64 *segment_cmd = (struct segment_command_64*)cur_cmd;
      if (strcmp(segment_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_cmd = segment_cmd;
      }
    }
    
    cur_pointer += cur_cmd->cmdsize;
  }
  
  assert(linkedit_code_signature && linkedit_cmd);
  
  return linkedit_code_signature;

}

typedef struct __BlobIndex {
  uint32_t type;          /* type of entry */
  uint32_t offset;        /* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
  uint32_t magic;          /* magic number */
  uint32_t length;        /* total length of SuperBlob */
  uint32_t count;          /* number of index entries following */
  CS_BlobIndex index[];      /* (count) entries */
  /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;



__attribute__((used)) static uint32_t SuperBlobGetMagic(CS_SuperBlob *b) {
  return  ntohl(b->magic);
}

__attribute__((used))  static uint32_t SuperBlobGetLength(CS_SuperBlob *b) {
  return  ntohl(b->length);
}

static uint32_t SuperBlobGetCount(CS_SuperBlob *b) {
  return  ntohl(b->count);
}

int main(int argc, const char * argv[], const char *enp[]) {
  @autoreleasepool {
    
    FILE * pFile;
    long lSize;
    char * buffer;
    size_t result;
    if (argc != 2) {
      fprintf(stderr, "%s /path/to/program/with/entitlements\n", basename((char *)argv[0]));
      return 1;
    }
    pFile = fopen ( argv[1], "r" );
    if (pFile== NULL) {
      fputs("File error", stderr);
      exit(1);
    }
    
    // obtain file size:
    fseek(pFile , 0 , SEEK_END);
    lSize = ftell(pFile);
    rewind(pFile);
    
    // allocate memory to contain the whole file:
    buffer = (char*) malloc (sizeof(char)*lSize);
    if (buffer == NULL) {fputs ("Memory error",stderr); exit (2);}
    
    // copy the file into the buffer:
    result = fread(buffer, 1, lSize, pFile);
    if (result != lSize) {fputs ("Reading error",stderr); exit (3);}
    
    /* the whole file is now loaded in the memory buffer. */
    
    
    
    struct linkedit_data_command *lc_code_sig = codesign_offset(buffer);
    
    fseek(pFile, lc_code_sig->dataoff, SEEK_SET);
    lSize = ftell (pFile);

    uintptr_t start_address = (uintptr_t)&buffer[lc_code_sig->dataoff];
    
    CS_SuperBlob * blob = (CS_SuperBlob *)start_address;

    
    for (int i = 0; i < SuperBlobGetCount(blob); i++) {
      CS_BlobIndex index = blob->index[i];

      if (ntohl(index.type) == 5) {
        
        char * entitlements = (char *)((uintptr_t)(blob) + ntohl(index.offset));
        
        
        // do entitlements always have 0xfa 0xde at begin/end?
        char* refined_entitlements = strdup((&entitlements[8]));
        refined_entitlements[strlen(refined_entitlements) - 2] = '\x00';
        
        NSPropertyListFormat format = 0;
        NSError *error = nil;
        refined_entitlements[strlen(refined_entitlements) - 2] = '\x00';

        NSString *strEntitlements = [NSString stringWithUTF8String:refined_entitlements];
        NSData *plistData = [strEntitlements dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:plistData options:NSPropertyListImmutable format:&format error:&error];
  
        
        fprintf(stdout, "%s\n%s\n", basename((char *)argv[1]), [[plist debugDescription] UTF8String]);
      }
    }
    fclose (pFile);
    
    
    
    free (buffer);

  }
  return 0;
}
