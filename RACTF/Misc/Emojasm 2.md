# Emojasm 2

```
β‘οΈπΌποΈπΌπ¦π¨   - Read T0 into A, store in X. 
β‘οΈποΈποΈποΈ       - Read T1 into A
π΄π¨π¦βοΈ      - AND A in place with X, store result in Y.
ποΈποΈ          - Read T1 back into A
π·π¨π¦π¨      - OR A in place with X, store result in X
π¦π¨π¦βοΈ      - DEC X, DEC Y
ββοΈ          - CMP Y 0
βοΈπππ·οΈ       - JNE 1D (decrement phase - this makes a subtraction loop,   
                subtracting Y from X, and leaving result in X.)
ππ¨π€        - Print X
β‘οΈπΌποΈπΌβ¬οΈπΌ    - Read the next char from T0 into A, move back.
βποΈ          - CMP A 0 (is the tape empty)
βοΈπππ·οΈ       - JNE 00
β‘οΈποΈποΈποΈβ¬οΈποΈ    - Read the next char from T1 into A, move back.
βπ          - CMP A 0 (same thing but makes sure both are empty
οΈβοΈπππ·οΈ       - JNE 00
πΏ            - HLT
```

This works because the difference between the AND of two numbers and the OR of those numbers, logically, is equal to the XOR. OR is also always greater than AND, as it has 1s in all the same places, and more.
#### Flag: ractf{x0rmoj1!}
