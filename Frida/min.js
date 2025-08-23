var mod = Process.getModuleByName('GameLogic.dll');
var baseAddr = mod ? mod.base : null;
console.log("GameLogic.dll base address:", baseAddr);

console.log("Memory.readU8:", typeof Memory.readU8);
console.log("Memory.writeU8:", typeof Memory.writeU8);
console.log("Memory.readFloat:", typeof Memory.readFloat);
console.log("Memory.writeFloat:", typeof Memory.writeFloat);

console.log("Process:", Process.id, Process.name);
console.log("Module:", typeof Module);
console.log("Memory.readU8:", typeof Memory.readU8);
console.log("Memory.readPointer:", typeof Memory.readPointer);
console.log("Interceptor.attach:", typeof Interceptor.attach);
