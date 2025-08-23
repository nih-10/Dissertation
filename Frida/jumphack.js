'use strict';

var mod = Process.getModuleByName('GameLogic.dll');
var GameLogicBase = mod.base; // ✅ the working base address
console.log("GameLogic.dll base address:", GameLogicBase);

// Example offsets from your exports (adjust for your target)
var PlayerCanJump = GameLogicBase.add(0x00051680);

var GameLogicPlayer = ptr(0);


// Force always-true jump
Interceptor.attach(PlayerCanJump, {
    onLeave: function (retval) {
        retval.replace(1);
        console.log("[*] Forced jump allowed");
    }
});


