//Open the target process with read , write and execute priviledges
   Process = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION, FALSE, ID); 

   //Get the address of LoadLibraryA
   LoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"); 

   // Allocate space in the process for our DLL 
   Memory = (LPVOID)VirtualAllocEx(Process, NULL, strlen(dll)+1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); 

   // Write the string name of our DLL in the memory allocated 
   WriteProcessMemory(Process, (LPVOID)Memory, dll, strlen(dll)+1, NULL); 

   // Load our DLL 
   CreateRemoteThread(Process, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibrary, (LPVOID)Memory, NULL, NULL); 

   //Let the program regain control of itself
   CloseHandle(Process); 
