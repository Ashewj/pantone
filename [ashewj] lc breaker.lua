require'vector'
local ffi             = require 'ffi'
-- local pui             = require 'lib/pui'
-- local hook            = require 'lib/hooks'
-- local c_entity        = require 'lib/entity'
-- local antiaim_funcs   = require 'lib/antiaim_funcs'
-- local extended_events = require 'lib/extended_events'

-- _G._DEBUG = false

local INT_MAX = 2139095039

-- local gui = pui.group("Lua", "B")

local ffi_cdef, ffi_cast, ffi_new, ffi_typeof, ffi_sizeof, ffi_string, ffi_copy, ffi_fill = ffi.cdef, ffi.cast, ffi.new, ffi.typeof, ffi.sizeof, ffi.string, ffi.copy, ffi.fill
local bit_band, bit_bor, bit_bnot, bit_lshift, bit_rshift = bit.band, bit.bor, bit.bnot, bit.lshift, bit.rshift

local nullptr = ffi_new('void*')
local nullchar = ffi_new('char*')

local g_BitWriteMasks = ffi_new("uint32_t[32][33]")
local g_ExtraMasks = ffi_new("uint32_t[32]")

function debug_print(...)
    -- if _DEBUG then
        client.color_log(255, 209, 220, "[ ashewj| ] \0")
        client.color_log(255, 105, 97, ...)
    -- end
end

(function()
    for startbit = 0, 31 do
        for nBitsLeft = 0, 32 do
            local endbit = startbit + nBitsLeft
            g_BitWriteMasks[startbit][nBitsLeft] = bit_lshift(1, startbit) - 1

            if endbit < 32 then
                g_BitWriteMasks[startbit][nBitsLeft] = bit_bor(
                    g_BitWriteMasks[startbit][nBitsLeft],
                    bit_bnot(bit_lshift(1, endbit) - 1)
                )
            -- print(g_BitWriteMasks[startbit][nBitsLeft])
            end
        end
    end

    for maskBit = 0, 31 do
        g_ExtraMasks[maskBit] = bit_lshift(1, maskBit) - 1
    end
end)()

local typeof_cache = {}
local vtable_func_cache = {}
local function vtable_bind(class, _type_str, index)
    local ffitype = typeof_cache[_type_str]
    if not ffitype then
        ffitype = ffi.typeof(_type_str)
        typeof_cache[_type_str] = ffitype
    end

    local class_addr = tonumber(ffi.cast("uintptr_t", class))
    local cache_key = string.format("%x_%d", class_addr, index)

    local fn = vtable_func_cache[cache_key]
    if fn then return fn end

    local this = ffi.cast("void***", class)
    fn = function(...)
        return ffi.cast(ffitype, this[0][index])(this, ...)
    end

    vtable_func_cache[cache_key] = fn
    return fn
end

ffi_cdef[[
    typedef struct {
        uint32_t ground_handle;
        bool in_prediction;
        bool old_in_prediction;
        char pad_1[0x2]; // PAD(2);
        int32_t prev_start_frame;
        int32_t incoming_packet_number;
        float time_stamp;
        bool is_first_time_predicted;
        char pad_2[0x3]; // PAD(3);
        int32_t commands_predicted;
        int32_t server_commands_acknowledged;
        int32_t prev_ack_had_errors;
        float ideal_pitch;
        uint32_t last_cmd_acknowledged;
        bool trigger_latch_reset;
    } c_prediction;

    typedef struct {
        char   pad0[0x14];             //0x0000
        bool        bProcessingMessages;    //0x0014
        bool        bShouldDelete;          //0x0015
        char   pad1[0x2];              //0x0016
        int         iOutSequenceNr;         //0x0018 last send outgoing sequence number
        int         iInSequenceNr;          //0x001C last received incoming sequence number
        int         iOutSequenceNrAck;      //0x0020 last received acknowledge outgoing sequence number
        int         iOutReliableState;      //0x0024 state of outgoing reliable data (0/1) flip flop used for loss detection
        int         iInReliableState;       //0x0028 state of incoming reliable data
        int         iChokedPackets;         //0x002C number of choked packets
        char   pad2[0x414];            //0x0030
    } INetChannel; // Size: 0x0444
    
    typedef struct {
        float clock_offsets[16];
        int cur_clock_offset;
        int server_tick;
        int client_tick;
    } c_clock_drift_manager;

    typedef void*(*create_client_class)(int, int);
    typedef void*(*create_event)();

    typedef struct {
        create_client_class create_fn;
        create_event create_event_fn;
        char* network_name;
        void* recv_table;
        void* next;
        int class_id;
    } c_clientclass;

    typedef struct {
        short class_id;
        char pad0[2];
        float delay;
        char pad1[4];
        c_clientclass* m_client_class;
        char pad2[40];
        void* next;
    } c_event_info;

    typedef struct {
        char pad_0[0x9C];
        INetChannel* net_channel;
        int challenge_nr;
        char pad_1[0x4];
        double connect_time;
        int retry_number;
        char pad_2[0x54];
        int signon_state;
        char pad_3[0x4];
        double next_cmd_time;
        int server_count;
        int current_sequence;
        char pad_4[0x8];
        c_clock_drift_manager clock_drift_mgr;
        int delta_tick;
        bool m_bPaused;
        char paused_align[3];
        int m_nViewEntity;
        int m_nPlayerSlot;
        int bruh;
        char m_szLevelName[260];
        char m_szLevelNameShort[80];
        char m_szGroupName[80];
        char pad_032[92];
        int max_clients;
        char pad_0314[18828];
        float m_nLastServerTickTime;
        bool m_bInSimulation;
        char pad_4C9D[3];
        int old_tickcount;
        float tick_remainder;
        float frame_time;
        int last_outgoing_command;
        int choked_commands;
        int last_command_ack;
        int last_server_tick;
        int command_ack;
        int sound_sequence;
        int last_progress_percent;
        bool is_hltv;
        char pad9[0x4B];
        Vector m_view_angles;
        char pad10[0xCC];
        c_event_info* m_events;
    } c_client_state;

    typedef struct {
        float realtime;
        int framecount;
        float absoluteframetime;
        float absoluteframestarttimestddev;
        float curtime;
        float frametime;
        int max_clients;
        int tickcount;
        float interval_per_tick;
        float interpolation_amount;
        int sim_ticks_this_frame;
        int network_protocol;
        void* save_data;
        bool client;
        int time_stamp_networking_base;
        int time_stamp_randomize_window;
    } c_global_vars;
 
    typedef struct {
        unsigned char* data;
        int dataBytes;
        int dataBits;
        int curBit;
        bool overflow;
        bool assertOnOverflow;
        const char* debugName;
    } bufferWrite;

    typedef struct 
    {
        uint32_t INetMessage_vtable; // 0x58 88 0
        uint32_t CCLCMsg_Move_vtable; // 0x54 84 4
        int unknown1; // 0x4c 80 8
        int m_nBackupCommands; // 0x4c 76 12
        int m_nNewCommands; // 0x48 72 16
        uintptr_t allocatedmemory; // 0x44 68 20
        int someint3; // 0x40 64 24
        int flags; // 0x3c 60 28
        char unknown3; // 0x38 64 32
        unsigned char pad0[3]; // 65 33
        char unknown4; // 0x34 68 36
        unsigned char pad1[15]; // 69 37
        int unknown5; // 0x24 84 52
        int unknown; // 0x20 88 56
        bufferWrite m_DataOut;
    } CLC_Move;

    typedef struct {
        char vfptr_0x4[0x4];
        int command_number; // 4
        int tickcount; // 8
        Vector viewangles;
        Vector aim_direction;
        float forwardmove;
        float sidemove;
        float upmove;
        int buttons;
        int impulse;
        int weapon_select; // 56
        int weapon_sub_type; // 60
        int random_seed;
        short mouse_dx; // 68
        short mouse_dy; // 70
        bool has_been_predicted; // 72
        Vector headangles; //76
        int bits;
        char pad_0x8[0x8];
    } c_user_cmd;

    typedef struct  {
        c_user_cmd cmd;
        int crc;
    } c_verified_cmd;

    typedef struct {
        char pad_0xC[0xC];
        bool trackir_available;
        bool mouse_initialized;
        bool mouse_active;
        char pad_0x9A[0x9A];
        bool camera_in_third_person;
        char pad_0x2[0x2];
        char pad_0xC[0xC];
        char pad_0x38[0x38];
        c_user_cmd* commands;
        c_verified_cmd* verified_commands;
    } c_input;

    typedef struct
    {
        bool m_bClientBlend;		 //0x0000
        float m_flBlendIn;			 //0x0004
        void* m_pStudioHdr;			 //0x0008
        int m_nDispatchSequence;     //0x000C
        int m_nDispatchSequence_2;   //0x0010
        uint32_t m_nOrder;           //0x0014
        uint32_t m_nSequence;        //0x0018
        float m_flPrevCycle;       //0x001C
        float m_flWeight;          //0x0020
        float m_flWeightDeltaRate; //0x0024
        float m_flPlaybackRate;    //0x0028
        float m_flCycle;           //0x002C
        void* m_pOwner;              //0x0030
        char pad_0038[4];            //0x0034
    } animation_layer_t;

    typedef struct 
    {
	    bool needs_processing;
	    c_user_cmd user_cmd;
	    int cmd_number;
    } cmd_context_t;
    
    typedef struct
    {
      void* BaseAddress;
      void* AllocationBase;
      uint32_t AllocationProtect;
      size_t RegionSize;
      uint32_t State;
      uint32_t Protect;
      uint32_t Type;
    } MEMORY_BASIC_INFORMATION;

    typedef unsigned long DWORD;
    typedef void* LPVOID;
    typedef void* HANDLE;
    typedef DWORD(__stdcall *LPTHREAD_START_ROUTINE)(LPVOID lpParam);
    typedef int (__stdcall *LOCALE_ENUMPROCA)(const char*);

    typedef enum
    {
        // Unknown error. Should not be returned.
        MH_UNKNOWN = -1,
        // Successful.
        MH_OK = 0,
        // MinHook is already initialized.
        MH_ERROR_ALREADY_INITIALIZED,
        // MinHook is not initialized yet, or already uninitialized.
        MH_ERROR_NOT_INITIALIZED,
        // The hook for the specified target function is already created.
        MH_ERROR_ALREADY_CREATED,
        // The hook for the specified target function is not created yet.
        MH_ERROR_NOT_CREATED,
        // The hook for the specified target function is already enabled.
        MH_ERROR_ENABLED,
        // The hook for the specified target function is not enabled yet, or already
        // disabled.
        MH_ERROR_DISABLED,
        // The specified pointer is invalid. It points the address of non-allocated
        // and/or non-executable region.
        MH_ERROR_NOT_EXECUTABLE,
        // The specified target function cannot be hooked.
        MH_ERROR_UNSUPPORTED_FUNCTION,
        // Failed to allocate memory.
        MH_ERROR_MEMORY_ALLOC,
        // Failed to change the memory protection.
        MH_ERROR_MEMORY_PROTECT,
        // The specified module is not loaded.
        MH_ERROR_MODULE_NOT_FOUND,
        // The specified function is not found.
        MH_ERROR_FUNCTION_NOT_FOUND
    } MH_STATUS;
]]

local function to_wide(str)
    local buf = ffi_new("wchar_t[?]", #str + 1)
    for i = 1, #str do
        buf[i - 1] = str:byte(i)
    end
    buf[#str] = 0
    return buf
end

local function safe_call(d, ...)
    local e, f = pcall(d, ...)
    if not e then
        print(("Error: %s"):format(f))
        return nil
    end
    return f
end

local function relative(t, addr)
    return ffi_cast(ffi_typeof(t), addr + 4 + ffi_cast("int32_t*", addr)[0])
end

local function call_original(tt, aa)
    return ffi_cast(ffi_typeof(tt), ffi_cast("int32_t*", aa + 1)[0] + aa + 5);
end

local function clamp(min, max, value)
    return math.min(math.max(min, value), max)
end

-- local function copy(dst, src, len)
--     return ffi_copy(ffi_cast("void*", dst), ffi_cast("const void*", src), len)
-- end

local function casty(t, v)
    return tonumber(ffi_cast(t, v))
end

local function opcode_scan(module, pattern, offset)
    local sig = client.find_signature(module, pattern) 
    if not sig then
        error(string.format('failed to find signature: %s', module))
    end
    return ffi_cast('uintptr_t', sig) + (offset or 0)
end

local g_ctx = (function()
    local ctx = {
        patterns = {
            get_proc_address     = "\xFF\x15\xCC\xCC\xCC\xCC\xA3\xCC\xCC\xCC\xCC\xEB\x05",
            get_module_handle    = "\xFF\x15\xCC\xCC\xCC\xCC\x85\xC0\x74\x0B",
            client_state         = "\xA1\xCC\xCC\xCC\xCC\x8B\x80\xCC\xCC\xCC\xCC\xC3",
            input                = "\xB9\xCC\xCC\xCC\xCC\xF3\x0F\x11\x04\x24\xFF\x50\x10",
            global_vars          = "\xA1\xCC\xCC\xCC\xCC\xF3\x0F\x10\x40\xCC\x0F\x5A\xC0\xF2\x0F\x11\x04",
            write_user_cmd       = "\x55\x8B\xEC\x83\xE4\xF8\x51\x53\x56\x8B\xD9",
            get_checksum         = "\x53\x8B\xD9\x83\xC8\xFF",
            cl_move              = "\xE8\xCC\xCC\xCC\xCC\xFF\x15\xCC\xCC\xCC\xCC\xF2\x0F\x10\x05\xCC\xCC\xCC\xCC\xDC\x25\xCC\xCC\xCC\xCC\xDD\x5D\xCC\xF2\x0F\x58\x45\xCC\xF2\x0F\x11\x05\xCC\xCC\xCC\xCC\x85\xFF",
            cl_send_move         = "\x55\x8B\xEC\x8B\x4D\x04\x81\xEC\xCC\xCC\xCC\xCC",
            clc_set_data         = "\xE8\xCC\xCC\xCC\xCC\x8D\x7E\x18",
            clc_destructor       = "\xE8\xCC\xCC\xCC\xCC\xF6\x45\xCC\xCC\x74\xCC\x6A\x3C\x56\xE8\xCC\xCC\xCC\xCC\x83\xC4\x08\x8B\xC6\x5E\x5D\xC2\x04\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x8B\x15",
            setup_move           = "\xE8\xCC\xCC\xCC\xCC\x5F\x5B\x5D\xC2\x10\xCC",
            write_user_cmd_delta = "\x55\x8B\xEC\x83\xEC\x68\x53\x56\x8B\xD9\xC7"
        }
    }

    ctx.std_call_proxy = client.find_signature("client.dll", "\x51\xC3") -- push ecx, return
    ctx.jmp_ebx = client.find_signature("engine.dll", "\xFF\x23")
    ctx.jmp_ecx = client.find_signature("engine.dll", "\xFF\xE1")

    -- ctx.mem_alloc = ffi_cast("void**", ctx.GetProcAddress(ctx.GetModuleHandle("tier0.dll"), "g_pMemAlloc"))[0]
    ctx.client_state = ffi_cast("c_client_state***", opcode_scan("engine.dll", ctx.patterns.client_state) + 1)[0][0]
    ctx.client_static = ffi_cast("void*", ffi_cast("int32_t", ctx.client_state) + 0x8);
    ctx.input = ffi_cast("c_input**", opcode_scan("client.dll", ctx.patterns.input) + 1)[0]
    ctx.client = ffi_cast("void*", client.create_interface("client.dll", "VClient018"))
    ctx.engine = ffi_cast("void*", client.create_interface("engine.dll", "VEngineClient014"))
    ctx.prediction = ffi_cast("c_prediction*", client.create_interface("client.dll", "VClientPrediction001"))
    ctx.globals = ffi_cast("c_global_vars***", opcode_scan("client.dll", ctx.patterns.global_vars) + 1)[0][0]
    ctx.mdl_cache = ffi_cast("void*", client.create_interface("datacache.dll", "MDLCache004"))

    return ctx
end)()

local module_cache = {}
local GetModuleHandle = ffi_cast('uint32_t**', ffi_cast('uint32_t', client.find_signature('engine.dll', '\xFF\x15\xCC\xCC\xCC\xCC\x85\xC0\x74\x0B')) + 2)[0][0]
local static_get_module_handle = ffi_cast('uint32_t(__thiscall*)(unsigned int, const char*)', g_ctx.std_call_proxy)
local function cached_get_module_handle(module_name)
    if module_cache[module_name] ~= nil then
        return module_cache[module_name]
    end
    module_cache[module_name] = static_get_module_handle(GetModuleHandle, module_name)
    return module_cache[module_name]
end

local proc_cache = {}
local GetProcAddress = ffi_cast('uint32_t**', ffi_cast('uint32_t', client.find_signature('engine.dll', '\xFF\x15\xCC\xCC\xCC\xCC\xA3\xCC\xCC\xCC\xCC\xEB\x05')) + 2)[0][0]
local static_get_proc_address = ffi_cast('uint32_t(__thiscall*)(unsigned int, uint32_t, const char*)', g_ctx.std_call_proxy)
local function cached_get_proc_address(module_handle, function_name)
    local key = "ashewj" .. function_name
    if proc_cache[key] ~= nil then
        return proc_cache[key]
    end
    proc_cache[key] = static_get_proc_address(GetProcAddress, ffi_cast("uint32_t", module_handle), function_name)
    return proc_cache[key]
end

local call_cache = {}
local BindCall = function(type_str)
    local fn_type = call_cache[type_str]
    if not fn_type then
        fn_type = ffi_typeof(type_str)
        call_cache[type_str] = fn_type
    end
    return ffi_cast(fn_type, g_ctx.std_call_proxy)
end

local module_handle_cache = {}
local proc_address_cache = {}
local BindExport = function(ModuleName, FunctionName, TypeOf)
    local module_handle = module_handle_cache[ModuleName]
    if not module_handle then
        module_handle = cached_get_module_handle(ModuleName)
        module_handle_cache[ModuleName] = module_handle
    end

    if module_handle == nil then
        return nil
    end

    local proc_key = ModuleName .. "::" .. FunctionName
    local proc_address = proc_address_cache[proc_key]
    if not proc_address then
        proc_address = cached_get_proc_address(module_handle, FunctionName)
        proc_address_cache[proc_key] = proc_address
    end

    local wrapper_cache_key = proc_key .. "::" .. TypeOf
    if call_cache[wrapper_cache_key] then
        return call_cache[wrapper_cache_key]
    end

    local wrapper = function(...)
        return BindCall(TypeOf)(proc_address, ...)
    end

    call_cache[wrapper_cache_key] = wrapper
    return wrapper
end

local type_cache = {}
local cast_cache = {}
local BindFunction = function(func, returntype, typeof, lib)
    if lib == nil then
        print("lib not loaded")
        return
    end
    local f = cached_get_proc_address(lib, func)
    if f == 0 then
        print("function not found or invalid", func)
        return
    end

    local type_key = returntype .. "(__thiscall*)(unsigned int, " .. typeof .. ")"

    local ftype = type_cache[type_key]
    if not ftype then
        ftype = ffi_typeof(type_key)
        type_cache[type_key] = ftype
    end

    local cast_key = type_key .. tostring(f)
    local casted_fn = cast_cache[cast_key]
    if not casted_fn then
        casted_fn = ffi_cast(ftype, g_ctx.std_call_proxy)
        cast_cache[cast_key] = casted_fn
    end

    return function(...)
        return casted_fn(f, ...)
    end
end

local LoadLibraryExW = BindExport(
    "kernel32.dll", 
    "LoadLibraryExW", 
    "void*(__thiscall*)(unsigned int, const wchar_t*, void*, unsigned long)"
)

local FreeLibrary = BindExport(
    "kernel32.dll", 
    "FreeLibrary", 
    "bool(__thiscall*)(unsigned int, void*)"
)

local CreateThread = BindExport(
    "kernel32.dll",
    "CreateThread",
    "void*(__thiscall*)(unsigned int, void*, size_t, void*, void*, unsigned long, void*)"
)

local TerminateThread = BindExport(
    "kernel32.dll",
    "TerminateThread",
    "bool(__thiscall*)(unsigned int, void*, unsigned int)"
)

local CloseHandle = BindExport(
    "kernel32.dll",
    "CloseHandle",
    "bool(__thiscall*)(unsigned int, void*)"
)

local EnumSystemLocalesA = BindExport(
    "kernel32.dll",
    "EnumSystemLocalesA",
    "int(__thiscall*)(unsigned int, LOCALE_ENUMPROCA, unsigned int)"
)

local VirtualAlloc = BindExport(
    'kernel32.dll',
    'VirtualAlloc',
    'void*(__thiscall*)(unsigned int, void* lpAddress, size_t dwSize, unsigned long flAllocationType, unsigned long flProtect)'
)

local VirtualFree = BindExport(
    'kernel32.dll',
    'VirtualFree',
    'int(__thiscall*)(unsigned int, void* lpAddress, size_t dwSize, unsigned long dwFreeType)'
)

local VirtualQuery = BindExport(
    "kernel32.dll",
    "VirtualQuery",
    "size_t(__thiscall*)(unsigned int, const void*, MEMORY_BASIC_INFORMATION*, size_t)"
)

local memcpy = BindExport(
    "msvcrt.dll",
    "memcpy",
    "void*(__thiscall*)(unsigned int, void*, const void*, size_t)"
)

local memset = BindExport(
    "msvcrt.dll",
    "memset",
    "void*(__thiscall*)(unsigned int, void*, int, size_t)"
)

local MinHook = LoadLibraryExW(to_wide("D:\\csgo_legacy\\lua\\lib\\MinHook.dll"), nil, 0x00000008)
local MH_Initialize = BindFunction("MH_Initialize", "MH_STATUS", "void", MinHook)
local MH_Uninitialize = BindFunction("MH_Uninitialize", "MH_STATUS", "void", MinHook)
local MH_CreateHook = BindFunction("MH_CreateHook", "MH_STATUS", "void*, void*, void*", MinHook)
local MH_EnableHook = BindFunction("MH_EnableHook", "MH_STATUS", "void*", MinHook)
local MH_DisableHook = BindFunction("MH_DisableHook", "MH_STATUS", "void*", MinHook)
local MH_StatusToString = BindFunction("MH_StatusToString", "const char*", "MH_STATUS", MinHook)
 
local spoofcall = LoadLibraryExW(to_wide("D:\\csgo_legacy\\lua\\spoofcall.dll"), nil, 0x00000008)
local wrap_physicssimulate = BindFunction("wrap_physicssimulate", "void", "uintptr_t, uintptr_t, uintptr_t", spoofcall)
local wrap_clreadpackets = BindFunction("wrap_clreadpackets", "void", "uintptr_t, bool", spoofcall)
local wrap_clmove = BindFunction("wrap_clmove", "void", "uintptr_t, float, bool", spoofcall)
local wrap_findmdl = BindFunction("wrap_findmdl", "unsigned short", "uintptr_t, uintptr_t, char*", spoofcall)

MH_Initialize();

-- local Alloc = vtable_bind(g_ctx.mem_alloc, "void*(__thiscall*)(void*, int)", 1)
-- local Free = vtable_bind(g_ctx.mem_alloc, "void(__thiscall*)(void*, void*)", 5)

-- local _Alloc = ffi_cast('void***', g_ctx.mem_alloc)[0][1]
-- local Alloc = ffi_cast('void*(__thiscall*)(void*, int)', g_ctx.jmp_ecx)

local VClientEntityList = client.create_interface("client.dll", "VClientEntityList003")
local get_client_entity = vtable_bind(VClientEntityList, "void*(__thiscall*)(void*, int)", 3)

-- local WriteUsercmdDeltaToBuffer = vtable_bind(g_ctx.client, "bool*(__thiscall*)(void*, int, bufferWrite*, int, int, bool)", 24)
-- local WriteUserCmd = ffi_cast("void(__fastcall*)(bufferWrite*, c_user_cmd*, c_user_cmd*)", client.find_signature("client.dll", g_ctx.patterns.write_user_cmd));

local GetChecksum = ffi_cast("int(__fastcall*)(c_user_cmd*)", client.find_signature("client.dll", g_ctx.patterns.get_checksum))
-- local GetUserCmd = vtable_bind(g_ctx.input, "c_user_cmd*(__thiscall*)(void*, int, int)", 8)

local base = ffi_cast("uintptr_t*", ffi_cast("uint32_t", g_ctx.input) + 0xF0)[0]
local function GetUserCmdAshewj(sequence_number)
    local offset = (sequence_number % 150) * 100
    local ptr = ffi_cast("c_user_cmd*", base + offset)
    return ptr
end

local function GetUserCmd(n, sequence_number)
    -- local user_cmds = ffi_cast("c_user_cmd**", ffi_cast("uint32_t", g_ctx.input) + 0xF0)[0];
    -- return user_cmds[sequence_number % 150];
    return g_ctx.input.commands[sequence_number % 150]
end

local function GetVerifiedCmd(sequence_number)
    -- local verified_cmds = ffi_cast("c_verified_cmd**", ffi_cast("uint32_t", g_ctx.input) + 0xF4)[0];
    -- return verified_cmds[sequence_number % 150];
    return g_ctx.input.verified_commands[sequence_number % 150];
end

-- local SendNetMsg = vtable_thunk(40, "bool(__thiscall*)(INetChannel*, CLC_Move*, bool, bool)")
local send_net_msg = client.find_signature('engine.dll', '\x55\x8B\xEC\x83\xEC\x08\x56\x8B\xF1\x8B\x4D\x04')
local SendNetMsg = ffi_cast('bool( __thiscall*)( INetChannel*, CLC_Move*, bool, bool )', send_net_msg)
local SendDatagram = vtable_thunk(46, "int(__thiscall*)(void*, void*)")

local is_in_game = vtable_bind(g_ctx.engine, "bool(__thiscall*)(void*)", 26)
local is_connected = vtable_bind(g_ctx.engine, "bool(__thiscall*)(void*)", 27)
local get_net_channel = vtable_bind(g_ctx.engine, "INetChannel*(__thiscall*)(void*)", 78)
local fire_events = vtable_bind(g_ctx.engine, "void*(__thiscall*)(void*)", 59)

local get_average_latency = vtable_thunk(10, "float(__thiscall*)(void*, int)")
local is_loopback = vtable_thunk(6, "bool(__thiscall*)(void*)")

local Update = vtable_bind(g_ctx.prediction, "void(__thiscall*)(void*, int, bool, int, int)", 3)
local GetLocalViewAngles = vtable_bind(g_ctx.prediction, "void(__thiscall*)(void*, Vector&)", 12)
local SetLocalViewAngles = vtable_bind(g_ctx.prediction, "void(__thiscall*)(void*, Vector&)", 13)
local SetViewAngles = vtable_bind(g_ctx.prediction, "void(__thiscall*)(void*, Vector&)", 11)

local original_clreadpackets = ffi_new('uintptr_t[1]')
local original_clmove = ffi_new("uintptr_t[1]")
local original_findmdl = ffi_new("uintptr_t[1]")
local original_physicssimulate = ffi_new("uintptr_t[1]")

local clSendMove = opcode_scan("engine.dll", g_ctx.patterns.cl_send_move)
local CLC_SetData = relative("void(__thiscall*)(uintptr_t, const char*, size_t)", opcode_scan("engine.dll", g_ctx.patterns.clc_set_data) + 1);
local CLC_Destructor = relative("void(__thiscall*)(void*)", opcode_scan("engine.dll", g_ctx.patterns.clc_destructor) + 1);

local setupmove = relative("int32_t", opcode_scan("client.dll", g_ctx.patterns.setup_move) + 1);
local writetodeltabuffer = opcode_scan("client.dll", g_ctx.patterns.write_user_cmd_delta)

local target_clreadpackets = ffi_cast('void*', opcode_scan("engine.dll", "\x53\x8A\xD9\x8B\x0D\xCC\xCC\xCC\xCC\x56\x57\x8B\xB9"))
local target_clmove = relative("void*", opcode_scan("engine.dll", g_ctx.patterns.cl_move) + 1);
local target_clsendmove = ffi_cast('void*', clSendMove)
local target_physicssimulate = ffi_cast('void*', opcode_scan("client.dll", "\xC1\xE9\x10\x39\x48\xCC\x75\xCC\x8B\x08\x85\xC9\x74\xCC\x8B\x01\xFF\x90\xCC\xCC\xCC\xCC\xA1") - 27);

function WriteOneBit(buf, nValue)
    if buf.curBit + 1 > buf.dataBits then
    	buf.overflow = true;
    end

    local byte = ffi_cast("unsigned char*", bit_rshift(buf.curBit, 3) + buf.data)
    if not buf.overflow then
        if nValue then
            byte[0] = bit_bor(byte[0], bit_lshift(1, bit_band(buf.curBit, 7)))
        elseif not nValue then
    	    byte[0] = bit_band(byte[0], bit_bnot(bit_lshift(1, bit_band(buf.curBit, 7))))
        end
    	buf.curBit = buf.curBit + 1;
    end
end

function WriteUBitLong(buf, curData, numbits)
    if buf.curBit + numbits <= buf.dataBits then
        local curBitMasked = bit_band(buf.curBit, 31)
        local out = ffi_cast('unsigned int*', 4 * bit_rshift(buf.curBit, 5) + buf.data)
        local dWord = 4 * bit_rshift(buf.curBit, 5)
        out[0] = bit_bor(bit_band(out[0], g_BitWriteMasks[curBitMasked][numbits]), bit_lshift(curData, curBitMasked))
        if 32 - curBitMasked < numbits then
            local lsb_msb = ffi_cast('unsigned int*', buf.data + dWord + 4);
            lsb_msb[0] = bit_bor(bit_band(lsb_msb[0], g_BitWriteMasks[0][numbits - (32 - curBitMasked)]), bit_rshift(curData, (32 - curBitMasked)))
        end
        buf.curBit = buf.curBit + numbits
    else
        buf.curBit = buf.dataBits;
        buf.overflow = true;
    end
end

function WriteBits(buf, inData, bits)
    local out = ffi_cast("unsigned int*", inData)
    local bitsLeft = bits

    if bits + buf.curBit <= buf.dataBits then
        while bit_band(tonumber(ffi_cast("uintptr_t", inData + 1)), 3) ~= 0 do
            if bitsLeft <= 8 then break end
            WriteUBitLong(buf, ffi_cast('uint8_t*', out)[0], 8)
            out = ffi_cast("unsigned int*", ffi_cast("char*", out) + 1)
            bitsLeft = bitsLeft - 8
        end

        if bitsLeft >= 32 then
            if bit_band(buf.curBit, 7) ~= 0 then
                local bitsRight = bit_band(buf.curBit, 31)
                local bitsLeft = 32 - bitsRight
                local iBitsChanging = 32 + bitsLeft
                local bitMaskLeft = g_BitWriteMasks[bitsRight][32];
                local bitMaskRight = g_BitWriteMasks[0][bitsRight];

                local data = ffi_cast("unsigned char*", bit_rshift(buf.curBit, 5) + buf.data)

                while bitsLeft >= 32 do
                    local curData = ffi_cast("unsigned long*", out)[0]
                    out = out + ffi_sizeof("unsigned long");

                    data[0] = bit_bor(data[0], bit_lshift(curData, bitsRight))

                    data[0] = data[0] + 1;

                    if bitsLeft < 32 then
                        curData = bit_rshift(curData, bitsLeft)
                        data[0] = bit_band(data[0], bitMaskRight)
                        data[0] = bit_bor(data[0], curData)
                    end

                    bitsLeft = bitsLeft - 32
                    buf.curBit = buf.curBit + 32
                end
            else
                local numbytes = bit_rshift(bitsLeft, 3)
                local numbits = bit_lshift(numbytes, 3)
                ffi_copy(buf.data + bit_rshift(buf.curBit, 3), out, numbytes)
                out = ffi_cast("unsigned int*", ffi_cast("char*", out) + numbytes)
                bitsLeft = bitsLeft - numbits
                buf.curBit = buf.curBit + numbits
            end
        end

        while bitsLeft >= 8 do
            WriteUBitLong(buf, ffi_cast('uint8_t*', out)[0], 8)
            out = ffi_cast("unsigned int*", ffi_cast("char*", out) + 1)
            bitsLeft = bitsLeft - 8
        end

        if bitsLeft ~= 0 then
            WriteUBitLong(buf, ffi_cast('uint8_t*', out)[0], bitsLeft)
        end
        return not buf.overflow
    else
        buf.overflow = true;
        return false
    end
end

function WriteSBitLong(buf, data, numbits)
    local value = data
    local preserveBits = bit_rshift(0x7FFFFFFF, 32 - numbits)
    local signExtension = bit_band(bit_rshift(value, 31), bit_bnot(preserveBits))
    value = bit_band(value, preserveBits)
    value = bit_bor(value, signExtension)

    WriteUBitLong(buf, value, numbits)
end

function WriteShort(buf, val)
	WriteSBitLong(buf, val, bit_lshift(ffi_sizeof('short'), 3));
end

function WriteUserCmdDeltaInt(buf, from, to, bits)
	if from ~= to then
		WriteOneBit(buf, true);
		WriteUBitLong(buf, to, bits);
		return true;
    end
	WriteOneBit(buf, false);
	return false;
end

function WriteUserCmdDeltaFloat(buf, from, to) 
	if from ~= to then
		WriteOneBit(buf, true);
        WriteBits(buf, ffi_cast("uint8_t*", ffi_new("float[1]", to)), 32)
		return true;
    end

	WriteOneBit(buf, false);
	return false;
end

function WriteUserCmdDeltaShort(buf, from, to)
	if from ~= to then
		WriteOneBit(buf, true);
		WriteShort(buf, to);
		return true;
	end

	WriteOneBit(buf, false);
	return false;
end

function WriteUserCmd(buf, to, from) 
    -- print(string.format("WriteUsercmd: from=%d to=%d", from.command_number, to.command_number))
    
	WriteUserCmdDeltaInt(buf, from.command_number + 1, to.command_number, 32);
	WriteUserCmdDeltaInt(buf, from.tickcount + 1, to.tickcount, 32);
    WriteUserCmdDeltaFloat(buf, from.viewangles.x, to.viewangles.x);
	WriteUserCmdDeltaFloat(buf, from.viewangles.y, to.viewangles.y);
	WriteUserCmdDeltaFloat(buf, from.viewangles.z, to.viewangles.z);
	WriteUserCmdDeltaFloat(buf, from.aim_direction.x, to.aim_direction.x);
	WriteUserCmdDeltaFloat(buf, from.aim_direction.y, to.aim_direction.y);
	WriteUserCmdDeltaFloat(buf, from.aim_direction.z, to.aim_direction.z);
	WriteUserCmdDeltaFloat(buf, from.forwardmove, to.forwardmove);
	WriteUserCmdDeltaFloat(buf, from.sidemove, to.sidemove);
	WriteUserCmdDeltaFloat(buf, from.upmove, to.upmove);
	WriteUserCmdDeltaInt(buf, from.buttons, to.buttons, 32);
	WriteUserCmdDeltaInt(buf, casty("uint8_t", from.impulse), casty("uint8_t", to.impulse), 8);
	if WriteUserCmdDeltaInt(buf, from.weapon_select, to.weapon_select, 11) then
		WriteUserCmdDeltaInt(buf, from.weapon_sub_type, to.weapon_sub_type, 6);
    end
    WriteUserCmdDeltaShort(buf, casty("int16_t", from.mouse_dx), casty("int16_t", to.mouse_dx));
    WriteUserCmdDeltaShort(buf, casty("int16_t", from.mouse_dy), casty("int16_t", to.mouse_dy));
    WriteUserCmdDeltaFloat(buf, from.headangles.x, to.headangles.x);
	WriteUserCmdDeltaFloat(buf, from.headangles.y, to.headangles.y);
	WriteUserCmdDeltaFloat(buf, from.headangles.z, to.headangles.z);
    WriteUserCmdDeltaInt(buf, from.bits, to.bits, 32);
end

local cached_clc_move = ffi_new("CLC_Move")

local INetMessage_vtable  = ffi_cast("uint32_t*",  clSendMove + 126)[0]
local CCLCMsg_Move_vtable = ffi_cast("uint32_t*",  clSendMove + 138)[0]
local allocated_memory    = ffi_cast("uintptr_t*", clSendMove + 131)[0]

function CLC_Constructor()
    cached_clc_move.INetMessage_vtable  = INetMessage_vtable
    cached_clc_move.CCLCMsg_Move_vtable = CCLCMsg_Move_vtable
    cached_clc_move.allocatedmemory     = allocated_memory
    cached_clc_move.unknown             = 15
    cached_clc_move.flags               = 3
    
    cached_clc_move.unknown1 = 0
    cached_clc_move.someint3 = 0
    cached_clc_move.unknown3 = 0
    cached_clc_move.unknown4 = 0
    cached_clc_move.unknown5 = 0

    return cached_clc_move;
end

local cached_dataout = cached_clc_move.m_DataOut

function StartWriting(ptr)
	cached_dataout.data = ptr;
	cached_dataout.dataBytes = 4000;
    cached_dataout.dataBits = 32000;
	cached_dataout.curBit = 0;
	cached_dataout.overflow = false;
end

function SetData(data_hack)
	data_hack.flags = bit_bor(data_hack.flags, 4)
    if data_hack.allocatedmemory == allocated_memory then
        local memory = VirtualAlloc(nil, 24, bit_bor(0x1000, 0x2000), 0x40)
        if memory ~= nil then
            ffi_cast("int*", ffi_cast("uint32_t",memory)+20)[0] = 15;
            ffi_cast("int*", ffi_cast("uint32_t",memory)+16)[0] =  0;
            ffi_cast("unsigned char*", memory)[0] =  0;
            ffi_copy(ffi_cast("void*", data_hack.allocatedmemory), memory, 24);
            VirtualFree(memory, 0, 0x8000)
        end
    end
    CLC_SetData(data_hack.allocatedmemory, data_hack.m_DataOut.data, bit_rshift(data_hack.m_DataOut.curBit + 7, 3));
end

function ValidateUserCmd(user_cmd, sequence_number) -- Validate that the user_cmd hasn't been changed
	local crc = GetChecksum( user_cmd );
	local verified_cmd = GetVerifiedCmd( sequence_number );
	if crc ~= verified_cmd.crc then 
        return verified_cmd.cmd;
    end
    return user_cmd;
end

function write_tick( cmdnum )
    local cmd = GetUserCmd( 0, cmdnum );
	local verified = GetVerifiedCmd( cmdnum );
    
    cmd.bits = cmd.buttons
    cmd.headangles = cmd.viewangles
    
	verified.cmd = cmd[0];
	verified.crc = GetChecksum( verified.cmd );
end

local nullcmd = ffi_new("c_user_cmd");
local f = ffi.new("c_user_cmd")
local t = ffi.new("c_user_cmd")

function WriteUsercmdDeltaToBuffer(from, to, forcevalid)
    local startbit = cached_dataout.curBit

    if from == -1 then
        ffi_copy(f, nullcmd, 100)
    else
        local f_cmd = GetUserCmdAshewj(from)
        --[[if f_cmd ~= nil then
            ffi_copy(f, f_cmd, 100)
            if not forcevalid then
                ValidateUserCmd(f, from)
            end
        end]]
    end

    local t_cmd = GetUserCmdAshewj(to)
    --[[if t_cmd ~= nil then
        ffi_copy(t, t_cmd, 100)
        if not forcevalid then
            ValidateUserCmd(t, to)
        end
    end

    -- Write it into the buffer
    WriteUserCmd(cached_dataout, t, f)

    if cached_dataout.overflow then
        local endbit = cached_dataout.curBit
        print(string.format("WARNING! User command buffer overflow(%d %d), last cmd was %d bits long", from, to, endbit - startbit))
        return false
    end]]

    return true
end

local IN_FORWARD   = bit_lshift(1, 3)
local IN_BACK      = bit_lshift(1, 4)
local IN_USE       = bit_lshift(1, 5)

local IN_MOVELEFT  = bit_lshift(1, 9)
local IN_MOVERIGHT = bit_lshift(1, 10)

local magic_number1 = 1;
local function slide_serversided(command_number)
    local current_cmd = GetUserCmd(0, command_number);
    current_cmd.buttons = bit_band(current_cmd.buttons, bit_bnot(bit_bor(IN_FORWARD, IN_BACK, IN_MOVELEFT, IN_MOVERIGHT)));
    
    if magic_number1 <= 1 then return end;

    local to_animate = command_number - magic_number1   

    for i = 0, to_animate do
        local cmd = GetUserCmd(0, magic_number1 + i);
        if cmd.command_number % 2 ~= (g_ctx.client_state.last_outgoing_command + g_ctx.client_state.choked_commands + 1) % 2 then
            if cmd.forwardmove ~= 0 then
                cmd.buttons = bit_bor(cmd.buttons, cmd.forwardmove < 0 and IN_FORWARD or IN_BACK)
            end
            if cmd.sidemove ~= 0 then
                cmd.buttons = bit_bor(cmd.buttons, cmd.sidemove < 0 and IN_MOVERIGHT or IN_MOVELEFT)
            end
        end   
        write_tick( cmd.command_number );
    end
end

--[[client.set_event_callback("run_command", function(c)
    if g_ctx.client_state.choked_commands <= 0 then
        magic_number1 = c.command_number;
    end

    slide_serversided(c.command_number)
    -- write_tick(c.command_number) -- look into this
end)]]

--[[
local main_c = ffi_cast("LPTHREAD_START_ROUTINE", function(lpParam)
    return 0;
end)

local tid = ffi_new("unsigned long[1]")
local thread = CreateThread(nil, 0, main_c, nil, 0, tid)
print("Thread ID: ", tid[0])]]

--[[
local left_attack = bit_lshift ( 1, 0 )
local right_attack = bit_lshift ( 1, 11 )
local in_use = bit_lshift ( 1, 5 )

local old_tickbase = -1
local last_tickb = -1
]]

local dt_lag_ref = ui.reference("RAGE", "Aimbot", "Double tap fake lag limit")
local dt_, dt_toggle_ref = ui.reference("RAGE", "Aimbot", "Double tap")

local function PING_REDUCER()
    return {
        data = {
            curtime = 0,
            frametime = 0,
            tickcount = 0,
            cs_tickcount = 0
        },
        store = function(self)
            local d = self.data
            d.curtime      = g_ctx.globals.curtime
            d.frametime    = g_ctx.globals.frametime
            d.tickcount    = g_ctx.globals.tickcount
            d.cs_tickcount = g_ctx.client_state.old_tickcount
        end,
        restore = function(self)
            local d = self.data
            g_ctx.globals.curtime            = d.curtime
            g_ctx.globals.frametime          = d.frametime
            g_ctx.globals.tickcount          = d.tickcount
            g_ctx.client_state.old_tickcount = d.cs_tickcount
        end
    }
end

local backup = PING_REDUCER()
local ping_backup = PING_REDUCER()

function available()

	if not is_connected() or not is_in_game() or g_ctx.client_state.net_channel == nil then
		return false;
    end

    -- if is_loopback(g_ctx.client_state.net_channel) then
	-- 	return false;
    -- end 

	return true;
end

function should_reduce_ping()

    if not available() then
        return false; 
    end

    ping_backup:restore();

    return true; 
end

function update_ping_values(final_tick)
	if not available() then
		return;
    end

	backup:store();

    wrap_clreadpackets(original_clreadpackets[0], final_tick)
    wrap_clreadpackets(original_clreadpackets[0], final_tick)
    
	ping_backup:store();
	backup:restore();
end

local clreadpackets_t = ffi_typeof("void(__cdecl*)(bool)")
hooked_clreadpackets = ffi_cast(clreadpackets_t, function(final_tick)
    if not should_reduce_ping() then 
        wrap_clreadpackets(original_clreadpackets[0], final_tick)
    else
        Update(g_ctx.client_state.delta_tick, g_ctx.client_state.delta_tick > 0, g_ctx.client_state.last_command_ack, g_ctx.client_state.last_outgoing_command + g_ctx.client_state.choked_commands)
        fire_events();
    end
end)

local clmove_t = ffi_typeof("void(__cdecl*)(float, bool)")
hooked_clmove = ffi_cast(clmove_t, function(accumulated_extra_samples, final_tick)
    if available() then
        update_ping_values(final_tick);
    end
    
    wrap_clmove(original_clmove[0], accumulated_extra_samples, final_tick)
end)

hooked_physicssimulate = ffi_cast("void(__fastcall*)(uintptr_t, uintptr_t)", function(player, edx)
    
    -- local cmd_context = ffi_cast("cmd_context_t*", player + 0x350C); 
    -- local context_tickcount = cmd_context[0].user_cmd.tickcount
    -- local simulation_tick = ffi_cast("int*", player + 0x2AC)[0]; 

    wrap_physicssimulate(original_physicssimulate[0], player, edx);
end)

local last_ticks_allowed = -1
local last_tickcount = -1
local last_shooting = -1

local data_shared = ffi_new("unsigned char[4000]");
local data_shared_ptr = ffi_cast("unsigned char*", data_shared)

local clsendmove_t = ffi_typeof("void(__cdecl*)(void)")
hooked_clsendmove = ffi_cast(clsendmove_t, function()

    local moveMsg = CLC_Constructor();
    ffi_fill(data_shared, 4000, 0);
    StartWriting(data_shared_ptr);
        
    local current_commands = g_ctx.client_state.choked_commands;
        
    moveMsg.m_nNewCommands = current_commands + 1;
    local nextcommandnr = g_ctx.client_state.last_outgoing_command + moveMsg.m_nNewCommands;

    local from = -1;
    local bOK = true;

    --[[ local player = ffi_cast('uintptr_t', get_client_entity(entity.get_local_player()))
    local cmd_context = ffi_cast("cmd_context_t*", player + 0x350C); 
    local context_tickcount = cmd_context[0].user_cmd.tickcount

    local freeze_period = entity.get_prop(entity.get_game_rules(), "m_bFreezePeriod") -- m_bWarmupPeriod
    local doubletap_on = ui.get(dt_toggle_ref)

    local lc_left = (GetUserCmd(0, nextcommandnr).tickcount - context_tickcount)
    local ticks_allowed = GetUserCmd(0, nextcommandnr).tickcount - last_tickcount ~= 2 and context_tickcount ~= INT_MAX
    local ticks_charged = ticks_allowed and last_ticks_allowed
        
    local lc_defensive = freeze_period ~= 1 -- and doubletap_on 
                    and lc_left <= 1 and ticks_charged and context_tickcount ~= INT_MAX
        
    last_tickcount = GetUserCmd(0, nextcommandnr).tickcount;
    last_ticks_allowed = ticks_allowed

    -- ui.set(dt_lag_ref, 1);
    -- print(lc_defensive, " | ", lc_left, " | ",  GetUserCmd(0, nextcommandnr).tickcount ) -- , " | ", last_tickcount," | ", GetUserCmd(0, nextcommandnr).tickcount - last_tickcount

    if lc_defensive or bit_band(GetUserCmd(0, nextcommandnr).buttons, bit_lshift(1, 0)) ~= 0 or last_shooting ~= 0 then
        -- ui.set(dt_lag_ref, 3);
        -- write_tick(GetUserCmd(0, nextcommandnr).command_number)
        -- g_ctx.client_state.net_channel.iOutSequenceNr = g_ctx.client_state.net_channel.iOutSequenceNr - 1;
        -- g_ctx.client_state.net_channel.iOutSequenceNr = g_ctx.client_state.net_channel.iOutSequenceNr + 13;
        -- GetUserCmd(0, nextcommandnr).tickcount = GetUserCmd(0, nextcommandnr).tickcount - 8
    end
      
    last_shooting = bit_band(GetUserCmd(0, nextcommandnr).buttons, bit_lshift(1, 0))
    
    print(current_commands) ]]
    
    for to = nextcommandnr - moveMsg.m_nNewCommands + 1, nextcommandnr do
        bOK = bOK and WriteUsercmdDeltaToBuffer(from, to, true);
        from = to;
    end
    
    --[[if bOK then
        SetData(moveMsg);
        SendNetMsg(g_ctx.client_state.net_channel, moveMsg, false, false);
    end]]

    CLC_Destructor(moveMsg);
end)

local target_findmdl = ffi_cast("void***", g_ctx.mdl_cache)[0][10] -- correct

local findmdl_t = ffi_typeof("unsigned short(__fastcall*)(uintptr_t, uintptr_t, char*)")
hooked_findmdl = ffi_cast(findmdl_t, function(ecx, edx, path)
    print(ffi_string(path))

    if string.find(ffi_string(path), "knife_default_ct.mdl") then
        ffi_copy(path, "models/weapons/v_butterfly_ashewj.mdl")
    end

    return wrap_findmdl(original_findmdl[0], ecx, path)
end)

jit.off(hooked_clsendmove)
jit.off(hooked_clreadpackets)
jit.off(hooked_clmove)
jit.off(hooked_findmdl)
jit.off(hooked_physicssimulate)

MH_CreateHook(target_clsendmove, hooked_clsendmove, nil);
-- MH_CreateHook(target_clreadpackets, hooked_clreadpackets, original_clreadpackets);
-- MH_CreateHook(target_clmove, hooked_clmove, original_clmove);

-- MH_CreateHook(target_findmdl, hooked_findmdl, original_findmdl);
-- MH_CreateHook(target_physicssimulate, hooked_physicssimulate, original_physicssimulate);

MH_EnableHook(nil);

client.set_event_callback("paint_ui", function()
    local memoryUsed = collectgarbage("count")
    print("Memory used:", memoryUsed, "KB")
end)

client.set_event_callback("shutdown", function()
    MH_DisableHook(nil);
    MH_Uninitialize();

    FreeLibrary(MinHook);
    FreeLibrary(spoofcall);

    type_cache          = {};
    cast_cache          = {};
    call_cache          = {};
    module_handle_cache = {};
    proc_address_cache  = {};
    typeof_cache        = {};
    vtable_func_cache   = {};
    module_cache        = {};
    proc_cache          = {};

    -- TerminateThread(thread, 0); print("Thread ID: ",  tid[0], " terminated");

	local v1 = collectgarbage('count')
    collectgarbage('collect')
    collectgarbage('collect')
    local v2 = collectgarbage('count')
    local v3 = v1 - v2
    print('Memory cleared: ' .. string.format('%.2f', v3) .. ' KB')
end)