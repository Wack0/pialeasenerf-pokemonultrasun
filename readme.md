# pialease nerf payload for Pokémon Ultra Sun v2.2.0

The payload implemented here does the following, in ROP (for Ultra Sun v2.2.0):

- Creates a new pokemon object, of species Darkrai and level 100.
  - Heap id=11 is used for this, as the internal function that gives you Zygarde also uses this heap id.
- Sets its original trainer data to your save file's, and the cartridge version to Ultra Sun, so it will obey you in battle.
- Adds it to your party.
- Replaces your first party member with a clone of it.
- Sets your savefile location to the champion's room.
- Save and reset (uses a trick with an object destructor to save, and call it with lr=apt::RestartApplication).

I haven't done any more work with this in almost a year now, so might as well release it in this state.

I was unable to find a way to do stuff and cleanly return to the game, so doing stuff and then save+reset was the next best thing. The savefile location can be changed to the champion's room after you finish the battle but you're basically softlocked there afterwards as you're only supposed to be there when a script is executing (after you beat the champion).

You may only need one darkrai to beat the champion but given I didn't specify max-IVs or anything like that the pokemon generation is still RNG dependent, so setting max IVs could be an easy improvement.

Another possible improvement would be to figure out how to change the variable for the starter you picked, to give Hau an easier team to fight.

Additional improvement would be to port to wii u.

I only ever tested this on real hardware, not under any sort of emulation.

I got consistent sub-40 minute times when doing test runs, although I don't have a capture card so never recorded any of them. I tested with all three starters to see which one was best.

## Usage
- have your second 3DS running the exploit
- start your new game. Pick Litten or Popplio as starter (Rowlet was terrible in the earlygame)
- play normally until you get to the first pokemon center
- open the start menu, open quick link and start the quick link
- second 3DS should show the connection. on first 3DS, music will hang and then game will reset.
- load your save and you'll be in the champion's room, beat him with the level 100 darkrai you have and you're done.