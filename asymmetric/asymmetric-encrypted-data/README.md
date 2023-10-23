# Case Study :: Asymmetric Encrypted Data

![Technology - Spring Boot](https://img.shields.io/badge/Technology-Spring_Boot-blue)
![Tracing Difficulty - Easy](https://img.shields.io/badge/Tracing_Difficulty-Easy-green)
![Implementation Difficulty - Very Hard](https://img.shields.io/badge/Implementation_Difficulty-Very_Hard-purple)

## The Condition

You are developing an application, where some of the endpoint are required to validate and protect its payload, to prevent unwanted change and data leaks to unwanted person. So you need to implements Data Signature and Data Encryption algorithm within the application. And to simplify things, you are using JOSE standard to do these requirements.

## The Problem

Currently, only Object Signature is implemented on the endpoint, using JWS. The data are now validated and unchangeable, but it still readable in case that it is intercepted by men in the middle.

## The Objective

You need to implement Asymmetric Encryption in addition to the Object Signature, using JWE standard. You also need to implement Key Exchange and Key Store mechanism, so that clients will use different sets of key to encrypt their payload, therefore there is less chance of the data being leaked.

## The Expected Result

The returned response from the endpoint must be in JWE, instead of JWS only.
