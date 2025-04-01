from flask import Flask, render_template, request, jsonify
import sys, os, json, re, uuid, firebase_admin
from firebase_admin import credentials, db
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
import base64, secrets, time
from Crypto.Cipher import AES
from datetime import datetime
import random


def measure_time(func):
  def wrapper(*args, **kwargs):
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    execution_time = (end_time - start_time) * 1000
    return execution_time
  return wrapper


class LM_PAEKS:
  def __init__(self, group):
    self.group = group
    self.g1 = group.random(G1) # A generator of G


  @measure_time
  def keygen_RS(self):
    self.d_RS1 = self.group.random(ZR) # secret key
    self.d_RS2 = self.group.random(ZR) # secret key
    self.d_RS3 = self.group.random(ZR) # secret key
    self.k = self.group.random(ZR) # secret key
    
    
    self.D_RS1 = self.d_RS1 * self.g1 # public key
    self.D_RS2 = self.d_RS2 * self.g1 # public key


  @measure_time
  def keygen_S(self):
    self.d_Si = self.group.random(ZR) # secret key
    self.D_Si = self.d_Si * self.g1 # public key

  
  @measure_time
  def keygen_R(self):
    self.d_Rj = self.group.random(ZR) # secret key
    self.D_Rj = self.d_Rj * self.g1 # public key

  @measure_time
  def registration(self):
    self.A_Rj = self.k * self.D_Rj
    
    
  @measure_time
  def paeks(self, w):
    self.r1 = self.group.random(ZR)
    # C1 = r1 * self.group.hash((self.d_Si * self.D_RS1), ZR) * self.D_RS2
    self.C1 = self.r1 * self.group.hash(self.group.serialize(self.d_Si * self.D_RS1), ZR) * self.D_RS2
    self.C2 = self.r1 * self.group.hash(w, G1)
    
    
    """测试算法时间时，注释下面三行"""
    # 生成相同密文，用于测试updpaeks的等值测试算法
    self.r_star = self.group.random(ZR)
    self.C1_star = self.r_star * self.group.hash(self.group.serialize(self.d_Si * self.D_RS1), ZR) * self.D_RS2
    self.C2_star = self.r_star * self.group.hash(w, G1)
    

  
  @measure_time
  def updkeygen(self):
    self.uki = self.d_RS3 / (self.d_RS2 * self.group.hash(self.group.serialize(self.d_RS1 * self.D_Si), ZR))


  @measure_time
  def updpaeks(self):
    self.C1_hat = self.uki * self.C1
    self.C1_hat_star = self.uki * self.C1_star
    
    # self.C1_hat = self.r1 * self.d_RS3 * self.g1
    # self.C1_hat_star = self.r_star * self.d_RS3 * self.g1
    
    pairing_left = pair(self.C1_hat, self.C2_star)
    pairing_right = pair(self.C1_hat_star, self.C2)
    
    result_updpaeks = (pairing_left == pairing_right)
    print(f'result_updpaeks: {result_updpaeks}')
    
    if result_updpaeks:
      print(f'deduplication successful')
    else:
      print(f'deduplication unsuccessful')


  @measure_time
  def trapdoor(self, w2):
    r2 = self.group.random(ZR)
    self.T1 = r2 * self.d_Rj * self.group.hash(w2, G1)
    self.T2 = r2 * self.A_Rj

  
  @measure_time
  def trantrap(self):
    self.T1_hat = self.k * self.T1
    self.T2_hat = self.d_RS3 * self.T2
  
  
  @measure_time
  def test(self):
    pairing1 = pair(self.C1_hat, self.T1_hat)
    pairing2 = pair(self.C2, self.T2_hat)
    print(f"\npairing1: {pairing1};\npairing2: {pairing2};\n")
    self.result = (pairing1 == pairing2)


if __name__ == "__main__":
  group = PairingGroup("SS512")
  paeks = LM_PAEKS(group)
  print(f"params:\ng1: {paeks.g1}\n")

  keygen_RS_time = paeks.keygen_RS()
  
  print(f"\nReceiver Server private key: {paeks.d_RS1};\n{paeks.d_RS2};\n{paeks.d_RS3};\n{paeks.k};\n")
  print(f"\nReceiver Server public key 1: {paeks.D_RS1}\nReceiver Server public key 2: {paeks.D_RS2}")
  
  keygen_S_time = paeks.keygen_S()
  
  print(f"\nSender private key: {paeks.d_Si}\nSender public key 1: {paeks.D_Si}")
  
  keygen_R_time = paeks.keygen_R()
  
  print(f"\nReceiver private key: {paeks.d_Rj}\nReceiver public key: {paeks.D_Rj}")

  registration_time = paeks.registration()
  
  
  
  keyword1 = "meeting"
  keyword2 = "meeting"
  # keyword2 = "BABABAB"
    

  paeks_time = paeks.paeks(keyword1)

  print(f"\nCiphertext C1: {paeks.C1}\nCiphertext C2: {paeks.C2}")

  updkeygen_time = paeks.updkeygen()
  print(f"\nuki: {paeks.uki}\n")

  updpaeks_time = paeks.updpaeks()
  print(f"\nCiphertext C1_hat: {paeks.C1_hat}")

  trapdoor_time = paeks.trapdoor(keyword2)
  print(f"\nTrapdoor T1: {paeks.T1}\nTrapdoor T2: {paeks.T2}")

  trantra_time = paeks.trantrap()
  print(f"\nTranTrap T1_hat: {paeks.T1_hat}\nTranTrap T2_hat: {paeks.T2_hat}")

  test_time = paeks.test()
  print(f'\nresult: {paeks.result}')
  
  print(f'\nkeygen_RS_time: {keygen_RS_time}\nkeygen_S_time: {keygen_S_time}\nkeygen_R_time: {keygen_R_time}\nregistration_time: {registration_time}')
  print(f'paeks_time: {paeks_time}')
  print(f'updkeygen_time: {updkeygen_time}\nupdpaeks_time: {updpaeks_time}\ntrapdoor_time: {trapdoor_time}\ntrantra_time: {trantra_time}\ntest_time: {test_time}\n')
  
  if paeks.result:
    print("\nTest successful")
  else:
    print("\nTest unsuccessful")
