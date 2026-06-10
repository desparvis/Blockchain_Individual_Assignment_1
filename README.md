# Blockchain Based Student Attendance System

## How to compile:

You will need a linux environment to compile this program. Use the command below:<br>
`gcc filename.c name -lssl -lcrypto`

## How to build and run the application:

The name is the executable file that will be given once you compile the C program. To run, use this command:<br>
`./name`

## Required libraries:

You need the following libraries(I assume you are using a Linux environment):<br>
GCC and Make with OpenSSL library: `sudo apt update` and
`sudo apt install build-essential libssl-dev`

## How to switch between transaction models

Once the program is executed, you have a menu that prompts you to choose between:
UTXO model or Account-balance model.
If you want to change the model, you have to exit the program by pressing Ctrl-C on the terminal.

## How to to set the mining difficulty

When the program is running and the transaction model has been chosen, you can input 9 to adjust the mining difficulty, it is from a range of 1 to 4 zeros that are in front of the hash.

## How to test mining simulations

WHen the programming is running and the transaction model has been chosen, you can input 3 to simulate solo mining, or you can input 4 to simulate pool mining

## Author

Credo Desparvis Gutabarwa
