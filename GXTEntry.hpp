#pragma once

#include <string>
#include <map>

#include "../injector/injector.hpp"
#include "../injector/hooking.hpp"

class GXTManager {

    typedef uint32_t HASH;
    typedef std::map<HASH, std::string> TextMap;
    typedef std::map<HASH, TextMap> TableMap;
    typedef const char* (__fastcall *GetType)(void*, int, const char*);

    struct Data {
        bool isEnabled = false;
        bool can_patch = true;
        bool isPatched = false;

        TableMap tMap;                        // Table of a map of strings
        injector::memory_pointer_raw GetText; // Store the raw pointer that CText::Get is located at
        injector::memory_pointer_raw BefGet;  // The previous offset for CText::Get (before patching)
        injector::memory_pointer_raw BefSamp; // The previous offset for the SAMP compatibility hooked func (before patching)
        injector::scoped_jmp         JmpHook;
    };

    static inline Data& data() {
        static Data data = {};
        return data;
    }
  
    static inline HASH GetHash(const char* key) {
        HASH fnv = (2166136261U);

        for (const char* bytes = key; *bytes; bytes++) {
            fnv = ((fnv * 16777619) ^ (HASH)(uint8_t(toupper(*bytes))));
        }

        return fnv;
    }
    
    static inline const char* FindFromKey(const char* key) {
        auto& tables = data().tMap;
        HASH keyHash = GetHash(key);
            
        for (auto t = tables.begin(); t != tables.end(); ++t) {
            auto it = t->second.find(keyHash);
            if (it != t->second.end())
                return it->second.data();
        }
        
        return nullptr;
    }

    static inline void MakeHook() {
        data().JmpHook.make_jmp(data().GetText, injector::raw_ptr(GxtHook), false);
    }

    static inline const char* __fastcall GxtHook(void* self, int, const char* key) {
        if (data().isEnabled) {
            const char* value = FindFromKey(key);

            if (value) {
                return value;
            }
        }

        injector::scoped_basic<5> save_hook;
        save_hook.save(data().GetText.get(), 5, false);
        // UnHook
        data().JmpHook.restore();

        auto result = ((GetType)data().GetText.get())(self, 0, key);
        MakeHook();

        return result;
    }

    static inline void patch() {
        if (!data().isPatched) {
            DWORD oldprotect = 0;
            data().isPatched = true;
            data().isEnabled = true;

            data().GetText = injector::memory_pointer(0x6A0050).get<void>();
            injector::UnprotectMemory(data().GetText, 5, oldprotect);
            MakeHook();
        }
    }

    static inline void SampFixHook() {
        patch();
        return ((void (*)()) data().BefSamp.get())();
    }

public:
    GXTManager() {
        if (GetModuleHandleA("samp.dll")) {
            data().can_patch = false;
            data().BefSamp = injector::MakeCALL(0x748CFB, injector::raw_ptr(SampFixHook));
        }
    }

    inline void add(const char* key, const char* value, HASH table = 0) {
        if (data().can_patch) {
            patch();
        }

        std::string str(value, value + strlen(value) + 1);
        data().tMap[table][GetHash(key)] = str;
    }

    inline void set(const char* key, const char* value, HASH table = 0) {
        add(key, value, table);
    }
};