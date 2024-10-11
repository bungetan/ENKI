#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// PE 파일 구조체 정의 (32비트 기준)
typedef struct {
    uint16_t e_magic;    // DOS MZ 헤더 매직 넘버
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;   // PE Header의 오프셋
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint16_t VirtualAddress;
    uint16_t Size;
} IMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint32_t Signature; // "PE\x00\x00"
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADER;

#define IMAGE_SIZEOF_SHORT_NAME     8

typedef struct {
    uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

IMAGE_DOS_HEADER DH;
IMAGE_NT_HEADER NH;
IMAGE_SECTION_HEADER *SH;
FILE* fileIn;

uint16_t RVAtoRAW(uint16_t RVA) {
    uint16_t raw = 0;
    for (int i = 0; i < NH.FileHeader.NumberOfSections; i++) {
        if (RVA >= SH[i].VirtualAddress && (i == NH.FileHeader.NumberOfSections - 1 || RVA < SH[i + 1].VirtualAddress)) {
            raw = RVA - SH[i].VirtualAddress + SH[i].PointerToRawData;
            break;
        }
    }
    return raw;
}

void printDosHeader() {
    printf("< DOS HEADER >\n");
    printf("| MZ Signature: %x %x(%c%c)\n", DH.e_magic & 0xff, (DH.e_magic & 0xff00) >> 8, DH.e_magic & 0xff, (DH.e_magic & 0xff00) >> 8);
    printf("| NT header offset: 0x%02x\n\n", DH.e_lfanew);
}

void printOptionalHeader() {
    printf("| Optional Magic: 0x%x", NH.OptionalHeader.Magic);
    printf(NH.OptionalHeader.Magic == 0x10b ? " -> (IMAGE_OPTIONAL_HEADER32) \n" : " -> (IMAGE_OPTIONAL_HEADER64) \n");
    printf("| Address of Entry Point: 0x%x\n", NH.OptionalHeader.AddressOfEntryPoint);
    printf("| Image Base: 0x%x\n", NH.OptionalHeader.ImageBase);
    printf("| Section Alignment: 0x%x\n", NH.OptionalHeader.SectionAlignment);
    printf("| File Alignment: 0x%x\n", NH.OptionalHeader.FileAlignment);
    printf("| Size of Image: 0x%x\n", NH.OptionalHeader.SizeOfImage);
    printf("| Size of Headers: 0x%x\n", NH.OptionalHeader.SizeOfHeaders);
    printf("| Subsystem: 0x%x\n", NH.OptionalHeader.Subsystem);
    printf("\n");
}

void printNTHeader() {
    printf("< NT HEADER >\n");
    printf("| Signature: %x %x(%c%c)\n", NH.Signature & 0xff, (NH.Signature & 0xff00) >> 8, NH.Signature & 0xff, (NH.Signature & 0xff00) >> 8);
    printf("| Number of Section: 0x%x\n", NH.FileHeader.NumberOfSections);
    printf("| Size of OptionalHeader: 0x%x\n", NH.FileHeader.SizeOfOptionalHeader);
    printf("| File Characteristics: 0x%x\n", NH.FileHeader.Characteristics);
    printOptionalHeader();
}

void printSectionHeader() {
    printf("< SECTION HEADER >\n");
    for (int i = 0; i < NH.FileHeader.NumberOfSections; i++) {
        printf("| Name: %.8s\n", SH[i].Name);
        printf("| Virtual Size: 0x%x\n", SH[i].Misc.VirtualSize);
        printf("| Virtual Address: 0x%x\n", SH[i].VirtualAddress);
        printf("| Size of Raw Data: 0x%x\n", SH[i].SizeOfRawData);
        printf("| Pointer of Raw Data: 0x%x\n", SH[i].PointerToRawData);
        printf("| Characteristics: 0x%x\n", SH[i].Characteristics);

        // Characteristics 출력
        printf("| Properties: ");
        if (SH[i].Characteristics & 0x00000020) {
            printf("Code ");
        }
        if (SH[i].Characteristics & 0x00000040) {
            printf("Initialized Data ");
        }
        if (SH[i].Characteristics & 0x00000080) {
            printf("Uninitialized Data ");
        }
        if (SH[i].Characteristics & 0x02000000) {
            printf("Discardable ");
        }
        if (SH[i].Characteristics & 0x04000000) {
            printf("Not Cached ");
        }
        if (SH[i].Characteristics & 0x08000000) {
            printf("Not Paged ");
        }
        if (SH[i].Characteristics & 0x10000000) {
            printf("Shared ");
        }
        if (SH[i].Characteristics & 0x20000000) {
            printf("Executable ");
        }
        if (SH[i].Characteristics & 0x40000000) {
            printf("Readable ");
        }
        if (SH[i].Characteristics & 0x80000000) {
            printf("Writable ");
        }

        printf("\n\n");
    }
}

int main(void) {
    char* filename = (char*)malloc(sizeof(char) * 256);
    printf("PE 파일 이름을 입력하세요: ");
    scanf("%s", filename);
    printf("\n");
    
    if ((fileIn = fopen(filename, "rb")) == NULL) {
        fputs("File Open Error!\n", stderr);
        free(filename);
        return 1;
    }

    fread(&DH, sizeof(IMAGE_DOS_HEADER), 1, fileIn); // IMAGE_DOS_HEADER
    printDosHeader(); // print IMAGE_DOS_HEADER
    fseek(fileIn, DH.e_lfanew, SEEK_SET); // find IMAGE_NT_HEADER
    fread(&NH, sizeof(IMAGE_NT_HEADER), 1, fileIn); // IMAGE_NT_HEADERS
    printNTHeader(); // print IMAGE_NT_HEADERS

    //printf("%d\n", sizeof(IMAGE_SECTION_HEADER));
    fseek(fileIn, 24, SEEK_CUR);
    SH = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * NH.FileHeader.NumberOfSections); // malloc with number of sections
    fread(&SH[0], sizeof(IMAGE_SECTION_HEADER), 1, fileIn);
    for (int i = 0; i < NH.FileHeader.NumberOfSections; i++)
    {
        fread(&SH[i], sizeof(IMAGE_SECTION_HEADER), 1, fileIn); //IMAGE_SECTION_HEADER
    }
    printSectionHeader(); // print IMAGE_SECTION_HEADER[]

    fclose(fileIn);
    free(filename);
    free(SH); // 메모리 해제
    return 0;
}