#include <iostream>
#include <string>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <fcntl.h>
#include <capstone/capstone.h>
#include <elf.h>
#include <fstream>
#include <unordered_map>
#include <vector>

using namespace std;

pid_t child_pid = -1;
string loaded_program;
uintptr_t entry_point = 0;
bool program_loaded = false;
uintptr_t exec_start = 0;
uintptr_t exec_end = 0;
uintptr_t load_base = 0;
vector<uintptr_t> exe_region;
unordered_map<uintptr_t, uint8_t> breakpoints;

vector<uintptr_t> bp_table;
/* next index to assign */
size_t bp_next_index = 0;
struct EntryInfo {
    uintptr_t entry;
    bool is_pie;
};

//===========================helper===========================================
bool check_region(uintptr_t addr){
    for(int i=0;i<exe_region.size();i+=2){
        if(exe_region[i]<=addr&&addr<=exe_region[i+1]){
            return false;
        }
    }
    return true;
}
uintptr_t exe_region_end_for(uintptr_t addr){
    for(int i=0;i+1<exe_region.size();i+=2){
        if(exe_region[i]<=addr&&addr<=exe_region[i+1]){
            return exe_region[i+1];
        }
    }
    return 0;
}
static string uint64_to_hex(uintptr_t v){
    stringstream ss;
    ss << hex << showbase << v;   // prints with 0x prefix
    return ss.str();
}
size_t register_bp_index(uintptr_t addr){
    /* push into vector so deleted indices remain holes */
    bp_table.push_back(addr);
    return bp_next_index++;           
}
//===========================================================================
void prompt() {
    cout << "(sdb) " << flush;
}
void info_reg() {
    user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs) != 0) {
        perror("ptrace GETREGS");
        return;
    }

    printf("$rax 0x%016llx\t\t$rbx 0x%016llx\t\t$rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
    printf("$rdx 0x%016llx\t\t$rsi 0x%016llx\t\t$rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
    printf("$rbp 0x%016llx\t\t$rsp 0x%016llx\t\t$r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
    printf("$r9  0x%016llx\t\t$r10 0x%016llx\t\t$r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
    printf("$r12 0x%016llx\t\t$r13 0x%016llx\t\t$r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
    printf("$r15 0x%016llx\t\t$rip 0x%016llx\t\t$eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
    
}

EntryInfo get_entry_point(const string& path) {
    ifstream file(path, ios::binary);
    Elf64_Ehdr ehdr;
    file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));

    EntryInfo info;
    info.entry = ehdr.e_entry;
    info.is_pie = (ehdr.e_type == ET_DYN);
    return info;
}


void find_executable_range(pid_t pid) {
    string maps_path = "/proc/" + to_string(pid) + "/maps";
    ifstream maps(maps_path);

    exec_start = UINTPTR_MAX;
    exec_end   = 0;
    exe_region.clear();
    string line;
    while (getline(maps, line)) {
        //cout<<hex<<line<<endl;
        // only r-xp 
        if (line.find(" r-xp ") == string::npos) continue;
        //if (line.find(loaded_program) == string::npos) continue;

        istringstream iss(line);
        string addr_range, perms, offset;
        iss >> addr_range >> perms >> offset;

        size_t dash      = addr_range.find('-');
        uintptr_t start  = stoul(addr_range.substr(0, dash),  nullptr, 16);
        uintptr_t end    = stoul(addr_range.substr(dash+1),   nullptr, 16);

        //cout<<"========="<<start<<","<<end<<","<<addr_range<<endl;

        if (start < exec_start) exec_start = start;
        if (end   > exec_end)   exec_end   = end;

        exe_region.push_back(start);
        exe_region.push_back(end);
        // check first
        if (load_base == 0) {
            uintptr_t file_offset = stoul(offset, nullptr, 16);
            load_base = start - file_offset;     
        }
    }

}

static inline uint8_t peek8(uintptr_t addr)
{
    uintptr_t base = addr & ~7UL;                 // 8-byte aligned, bitmask 11111....11000
    long word      = ptrace(PTRACE_PEEKTEXT, child_pid, base, nullptr);
    int  shift     = (addr & 7) * 8;              // 0..56 bits
    return static_cast<uint8_t>((word >> shift) & 0xff);
}

static inline void poke8(uintptr_t addr, uint8_t val)
{
    uintptr_t base = addr & ~7UL;
    long word      = ptrace(PTRACE_PEEKTEXT, child_pid, base, nullptr);
    int  shift     = (addr & 7) * 8;
    long mask      = 0xffL << shift;
    long patched   = (word & ~mask) | (static_cast<long>(val) << shift);
    ptrace(PTRACE_POKETEXT, child_pid, base, patched);
}


void break_at(const string& addr_str) {
    uintptr_t addr = stoul(addr_str, nullptr, 16);

    if (addr < exec_start || addr >= exec_end) {
        cout << "** the target address is not valid." << endl;
        return;
    }
    if (breakpoints.count(addr)) {                      // already set
        cout << "** set a breakpoint at 0x" << hex << addr << "." << endl;
        return;
    }

    uint8_t orig = peek8(addr);
    breakpoints[addr] = orig;
    poke8(addr, 0xcc);  
    size_t idx = register_bp_index(addr);                                // INT3
    cout << "** set a breakpoint at 0x" << hex << addr << "." << endl;
}
// breakpoint at RVA (offset from image base)
void break_rva(const string& off_str){
    uintptr_t offset;
    try {
        offset = stoul(off_str, nullptr, 16);
    } catch (...) {
        cout << "** the target address is not valid." << endl;
        return;
    }

    uintptr_t addr = load_base + offset;
    if (addr < exec_start || addr >= exec_end) {
        cout << "** the target address is not valid." << endl;
        return;
    }
    if (breakpoints.count(addr)) {
        cout << "** set a breakpoint at 0x" << hex << addr << "." << endl;
        return;
    }

    
    uint8_t orig = peek8(addr);          
    breakpoints[addr] = orig;
    poke8(addr, 0xCC);                   // int3
    size_t idx = register_bp_index(addr);
    cout << "** set a breakpoint at 0x" << hex << addr << "." << endl;
}

void info_break(){
    bool any = false;

    for (size_t i = 0; i < bp_table.size(); ++i) {
        if (bp_table[i] != UINTPTR_MAX) {
            if (!any) {
                cout << "Num     Address\n";
            }
            printf("%-7zu 0x%lx\n", i, bp_table[i]);
            any = true;
        }
    }
    if (!any) cout << "** no breakpoints." << endl;
}
void delete_break(){

}

void disassemble_instructions(pid_t pid, uintptr_t addr){
    
    find_executable_range(pid);
    for(int i=0;i<exe_region.size();i+=2){
        printf("[Range]: %lx ~ %lx\n",exe_region[i],exe_region[i+1]);
    }
    // Open 
    string mem_path = "/proc/" + to_string(pid) + "/mem";
    int mem_fd = open(mem_path.c_str(), O_RDONLY);
    if (mem_fd < 0) {
        perror("open mem");
        return;
    }
    // Seek 
    if (lseek(mem_fd, addr, SEEK_SET) == -1) {
        perror("lseek");
        close(mem_fd);
        return;
    }

    if (check_region(addr)) {
        cout << "** the address is out of the range of the executable region." << endl;
        return;
    }
    // Read bytes 
    
    size_t max   = exe_region_end_for(addr) - addr;   
    //cout<<"Max: "<<max<<endl;
    size_t to_rd = min<size_t>(32, max);
    //cout<<"to_rd: "<<to_rd<<endl;
    uint8_t buffer[to_rd];
    ssize_t bytes_read = read(mem_fd, buffer, to_rd);
    printf("Raw instruction bytes at 0x%lx:\n", addr);
    for (size_t i = 0; i < bytes_read; ++i) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");

    for (size_t i = 0; i < bytes_read; ++i) {
        uintptr_t curr_addr = addr + i;
        if (breakpoints.count(curr_addr)) {
            buffer[i] = breakpoints[curr_addr];  // restore original byte 
        }
    }

    // Capstone
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        cerr << "** failed to initialize Capstone." << endl;
        return;
    }
    //check
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, buffer, bytes_read, addr, 5, &insn);

    if (count > 0) {
        for (size_t i = 0; i < count; i++) {

            printf("      %lx: ", insn[i].address);
            for (int j = 0; j < insn[i].size; j++) {
                printf("%02x ", insn[i].bytes[j]);
            }
            // Pad 
            for (int j = insn[i].size; j < 8; j++) {
                printf("   ");
            }
            printf("%-10s %s\n", insn[i].mnemonic, insn[i].op_str);

        }
        cs_free(insn, count);
    } else {
        cerr << "** failed to disassemble instructions." << endl;
    }
    if(count<5){
        cout << "** the address is out of the range of the executable region." << endl;
    }
    cs_close(&handle);
}
void set_breakpoint_at_entry() {
    long original = ptrace(PTRACE_PEEKTEXT, child_pid, entry_point, 0);
    breakpoints[entry_point] = original & 0xff;  // save original byte

    // Replace first byte with 0xCC (int3)
    long patched = (original & ~0xff) | 0xcc;
    ptrace(PTRACE_POKETEXT, child_pid, entry_point, patched);
}
void load_program(const string& path) {
    if (program_loaded) {
        cout << "** program already loaded." << endl;
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(path.c_str(), path.c_str(), nullptr);
        perror("exec");
        exit(1);
    } else {
        int status;
        waitpid(pid, &status, 0);

        ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_EXITKILL);
        child_pid = pid;
        loaded_program = path;
        EntryInfo info = get_entry_point(path);

        find_executable_range(pid);
        entry_point = info.is_pie ? load_base + info.entry : info.entry;

        program_loaded = true;

        printf("** program '%s' loaded. entry point: 0x%lx.\n", path.c_str(), entry_point);
        printf("%lx, %lx\n", exec_start, exec_end);
        disassemble_instructions(pid, entry_point);

        // Set breakpoint at entry point
        if(info.is_pie){
            set_breakpoint_at_entry();
            ptrace(PTRACE_CONT, child_pid, nullptr, nullptr);
            int status;
            waitpid(child_pid, &status, 0);
        }

    }
}
bool handle_break_hit(user_regs_struct &regs)
{
    uintptr_t rip = regs.rip;
    printf("si RIP: %lx\n", rip);

    if (!breakpoints.count(rip)) return false;      

    cout << "** hit a breakpoint at 0x" << hex << rip << "." << endl;
    disassemble_instructions(child_pid, regs.rip);
    return true;
}

void step_instruction()
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
    uintptr_t rip = regs.rip;
    int status;
    // check on bp
    if (breakpoints.count(rip)) {

        poke8(rip, breakpoints[rip]);

        ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr);
        waitpid(child_pid, &status, 0);

        poke8(rip, 0xCC);

        ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
        rip = regs.rip;
    } else {
        // single step
        if (ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr) == -1) {
            perror("ptrace SINGLESTEP"); return;
        }
        waitpid(child_pid, &status, 0);
        if (WIFEXITED(status)) {
            cout << "** the target program terminated." << endl;
            program_loaded = false; child_pid = -1;
            return;
        }
        ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
        rip = regs.rip;
    }

    if (handle_break_hit(regs)) return;

    if (check_region(rip))
        cout << "** the address is out of the range of the executable region." << endl;
    else
        disassemble_instructions(child_pid, rip);
}


bool cont_break_hit(user_regs_struct &regs)
{
    uintptr_t rip = regs.rip;
    printf("cont RIP: %lx\n",rip);
    uintptr_t bp_addr = rip - 1;
    if (breakpoints.count(bp_addr)) {
        cout << "** hit a breakpoint at 0x" << hex << bp_addr << "." << endl;
        regs.rip = bp_addr;
        ptrace(PTRACE_SETREGS, child_pid, nullptr, &regs);
        disassemble_instructions(child_pid, bp_addr);
        return true;
    }

    return false;
}

void continue_exe() {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
    //check on bp already
    if (breakpoints.count(regs.rip)) {
        poke8(regs.rip, breakpoints[regs.rip]);
        ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr);
        waitpid(child_pid, nullptr, 0);
        poke8(regs.rip, 0xCC);
        ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
    }

    while (true) {
        ptrace(PTRACE_CONT, child_pid, nullptr, nullptr);
        int status; waitpid(child_pid, &status, 0);

        if (WIFEXITED(status)) {                         // program done
            cout << "** the target program terminated." << endl;
            program_loaded = false; child_pid = -1;
            return;
        }

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
            if (cont_break_hit(regs)) return;          // chekc my bp
        }
    }
}


int main(int argc, char* argv[]) {
    string line;
    // ./sdb ./hello
    if (argc >= 2) {
        load_program(argv[1]);
    }

    prompt();
    while (getline(cin, line)) {
        istringstream iss(line);
        string cmd;
        iss >> cmd;

        if (cmd == "load") {
            string path;
            iss >> path;
            load_program(path);
        } else if (!program_loaded) {
            cout << "** please load a program first." << endl;
        } else if (cmd == "info") {
            string subcmd;
            iss >> subcmd;
            if (subcmd == "reg") {
                info_reg();
            }else if(subcmd == "break"){
                info_break();
            }
        } else if(cmd == "break"){
            string hex;
            iss >> hex;
            break_at(hex);
        } else if(cmd == "breakrva"){
            string hex;
            iss >> hex;
            break_rva(hex);
        } 
        else if (cmd == "si") {
            step_instruction();
        } else if (cmd == "cont") {
            continue_exe();
}       else {
            cout << "** unknown command: " << cmd << endl;
        }

        prompt();
    }

    return 0;
}

