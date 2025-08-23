// injectedScript_win.js
'use strict';

function logExports(moduleName) {
    var mod = Process.getModuleByName(moduleName);
    console.log("[*] Module:", mod.name, "Base:", mod.base, "Size:", mod.size);

    var exports = mod.enumerateExports();
    console.log("[*] Exported symbols:");
    exports.forEach(function (e) {
        console.log("   " + e.type + " " + e.name + " @ " + e.address);
    });
}

function hookFunction(moduleName, symbolName, retType, argTypes, cc) {
    var addr = Module.findExportByName(moduleName, symbolName);
    if (!addr) {
        console.error("[!] Could not find symbol:", symbolName);
        return;
    }
    console.log("[+] Hooking:", symbolName, "at", addr);

    var fn = new NativeFunction(addr, retType, argTypes, cc || 'thiscall');

    Interceptor.attach(addr, {
        onEnter: function (args) {
            console.log("[*] " + symbolName + " called");
            // Example: log first arg
            console.log("    arg0:", args[0]);
        },
        onLeave: function (retval) {
            console.log("[*] " + symbolName + " returned:", retval);
        }
    });
    Interceptor.attach(addr, {
        onEnter: function (args) {
            // Read a string argument from pointer
            var username = Memory.readUtf8String(args[1]);
            console.log("Username:", username);

            // Read integer argument
            var id = args[0].toInt32();
            console.log("ID:", id);
        },
    });

    return fn;
}

rpc.exports = {
    init: function () {
        console.log("[*] Injected into:", Process.name);
        logExports("GameLogic.dll");

        // Test hook: replace with a real exported symbol you see in logs
        //hookFunction("GameLogic.dll", "?Chat@Player@@QEAAXPEBD@Z", 'void', ['pointer', 'pointer'], 'thiscall');
        //hookFunction("GameLogic.dll", "?Login@GameAPI@@QAEXPBD0@Z", "void", ["pointer", "pointer"], "thiscall");

    }
};
