# Asymmetric Encrypted Data

## Description

1. Client mengirimkan single-use public key ke server
2. Server mengembalikan public key server yang dikunci menggunakan public key single-use client dan juga tokenId sebagai cookie yang digunakan untuk membedakan public key milik server
3. Client mengirimkan public key baru yang dikunci menggunakan public key server dan cookie tokenId
4. Server mengembalikan data yang diminta yang dikunci menggunakan public key baru client

## Yang sudah dilakukan

1. Mengimplementasikan alur JWE tersebut

## Progress

100%
