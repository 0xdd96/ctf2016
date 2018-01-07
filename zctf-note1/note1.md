# 漏洞点
  明显的堆溢出
  在new函数中,content为256字节
  ```
  vnote_10 = malloc(0x170uLL);
  puts("Enter the title:");
  input(vnote_10 + 2, 64LL, 10LL);
  puts("Enter the type:");
  input(vnote_10 + 10, 32LL, 10LL);
  puts("Enter the content:");
  input(vnote_10 + 14, 256LL, 10LL);
  ```
  在edit函数中，input可以接收512字节的数据，明显溢出
  ```
  if ( vnoteptr_58 )
  {
    puts("Enter the new content:");
    input(vnoteptr_58 + 112, 512LL, 10LL);
    puts("Modify success");
  }
  ```
  这里由于这些堆结构使用链表存储的，所以这里在利用时是，利用堆溢出，将指针改为got表的某一位置，由此就可以利用程序中原有的操作，打印got表中的数据，并修改
