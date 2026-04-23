#ifndef WTF_BDCORE_H
#define WTF_BDCORE_H

struct _FILE_PARSING_STATE
{
  void *ParsingAPIs;
  std::byte gap8[4];
  int field_C;
  void *field_10;
  void * field_18;
  void * field_20;
  void * field_28;
  void * field_30;
  void * FileSeekPtr;
  void * field_40;
  void * field_48;
  int field_50;
  void * nTotalBytesReadFromFileToScan;
  size_t EndOfFileOffset;
  int field_68;
  void * field_70;
  int FileTotalParts_0;
  int nMaxBytesToRead;
  std::byte gap80[8];
  void * FileContent;
  std::byte gap90[12];
  int CurrentPartOfFileToMoveTO;
  int field_A0;
  void * hFileToScan;
  void * field_B0;
  std::byte gapB8[4];
  void * field_BC;
  std::byte gapC4[532];
  void * field_2D8;
  void * temp0;
  std::byte gap2E8[40];
  int malwareDetected;
  std::byte gap314[180];
  void * fnAllocateHeapBlock;
  std::byte gap3D0[328];
  int SystemTime;
  std::byte gap51C[8];
  void * field_524;
  std::byte gap52C[5186];
  char field_196E;
  char field_196F;
};

#endif // WTF_BDCORE_H
