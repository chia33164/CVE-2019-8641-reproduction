from base64 import b64encode, b64decode
from struct import pack, unpack

class PlistWriter:
  def __init__(self):
    self.parts = []
    self.indention = 0

  def emit(self, s):
    self.parts.append(s)

  def finish(self):
    result = '\n'.join(self.parts)
    self.parts = []
    self.indention = 0
    return result

class NSArchiver:
  def __init__(self):
    self.map = {}
    self.writer = PlistWriter()
    self.refs = []

  def _archive(self, val):
    if isinstance(val, Ref):
      idx = None
      if val in self.map:
        idx = self.map[val]
      else:
        idx = len(self.refs)
        self.map[val] = idx
        self.refs.append(val)
      self.writer.emit('<dict>')
      self.writer.emit('<key>CF$UID</key>')
      self.writer.emit('<integer>{}</integer>'.format(idx))
      self.writer.emit('</dict>')
    elif val is True:
      self.writer.emit('<true/>')
    elif val is False:
      self.writer.emit('<false/>')
    elif isinstance(val, str):
      self.writer.emit('<string>{}</string>'.format(val))
    elif isinstance(val, bytes):
      b64 = b64encode(val).decode('ascii')
      self.writer.emit('<data>{}</data>'.format(b64))
    elif isinstance(val, int):
      self.writer.emit('<integer>{}</integer>'.format(val))
    elif isinstance(val, float):
      self.writer.emit('<real>{}</real>'.format(val))
    elif isinstance(val, list):
      self.writer.emit('<array>')
      for e in val:
        self._archive(e)
      self.writer.emit('</array>')
    elif isinstance(val, dict):
      self.writer.emit('<dict>')
      for k, v in val.items():
        assert(isinstance(k, str))
        self.writer.emit('<key>{}</key>'.format(k))
        self._archive(v)
      self.writer.emit('</dict>')
    else:
      raise Exception("Cannot serialize value of type {}".format(type(val)))

  def archive(self, val):
    assert(isinstance(val, Ref))

    self.writer.emit('<?xml version="1.0" encoding="UTF-8"?>')
    self.writer.emit('<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">')
    self.writer.emit('<plist version="1.0">')
    self.writer.emit('<dict>')
    self.writer.emit('    <key>$archiver</key>')
    self.writer.emit('    <string>NSKeyedArchiver</string>')
    self.writer.emit('    <key>$objects</key>')
    self.writer.emit('    <array>')

    idx = 0
    self.refs = [null, val]

    while idx < len(self.refs):
      r = self.refs[idx]
      self.map[r] = idx
      self._archive(r.v)
      idx += 1

    self.writer.emit('</array>')
    self.writer.emit('<key>$top</key>')
    self.writer.emit('<dict>')
    self.writer.emit('<key>root</key>')
    self.writer.emit('<dict>')
    self.writer.emit('<key>CF$UID</key>')
    self.writer.emit('<integer>1</integer>')
    self.writer.emit('</dict>')
    self.writer.emit('</dict>')
    self.writer.emit('<key>$version</key>')
    self.writer.emit('<integer>100000</integer>')
    self.writer.emit('</dict>')
    self.writer.emit('</plist>')

    return self.writer.finish()

class Ref:
  def __init__(self, v):
    assert(not isinstance(v, Ref))
    self.v = v

  def __hash__(self):
    return id(self)

  def __cmp__(self, other):
    return id(self) == id(other)

  def __str__(self):
    return "ref({})".format(self.v)

# Converts the agument into a reference type.
def ref(obj):
  return Ref(obj)

def cls(hierarchy):
  return ref({
    "$classes": hierarchy,
    "$classname": hierarchy[0]
  })

def nsstring(content):
  return ref({
    '$class': nsstring_class,
    'NS.string': content,
  })

def nsmutablestring(content):
  return ref({
    '$class': nsmutablestring_class,
    'NS.string': content,
  })

def nsdictionary(vals):
  return ref({
    '$class': nsdictionary_class,
    'NS.keys': list(vals.keys()),
    'NS.objects': list(vals.values()),
  })

def nsdata(content):
  return ref({
    '$class': nsdata_class,
    'NS.data': content,
  })

def nsmutabledata(content):
  return ref({
    '$class': nsmutabledata_class,
    'NS.data': content,
  })


def nsarray(vals):
  return ref({
    '$class': nsarray_class,
    'NS.objects': vals
  })

def nsmutarray(vals):
  return ref({
    '$class': nsmutarray_class,
    'NS.objects': vals
  })

def old_style_array(vals, typeid, elemsize):
  d = {
    '$class': nskeyed_coder_old_style_array_class,
    'NS.count': len(vals),
    'NS.size': elemsize,
    'NS.type': typeid
    }
  for i, v  in enumerate(vals):
    d['${}'.format(i)] = v
  return ref(d)

null = ref("$null")
nsstring_class = cls(["NSString", "NSObject"])
nsmutablestring_class = cls(["NSMutableString", "NSString", "NSObject"])
ac_zeroing_string = cls(["ACZeroingString", "NSString", "NSObject"])
nsdata_class = cls(["NSData", "NSObject"])
nsmutabledata_class = cls(["NSMutableData", "NSData", "NSObject"])
nsvalue_class = cls(["NSValue", "NSObject"])
nskeyed_coder_old_style_array_class = cls(["_NSKeyedCoderOldStyleArray", "NSObject"])
nsarray_class = cls(["NSArray", "NSObject"])
nsdictionary_class = cls(["NSDictionary", "NSObject"])
nsmutarray_class = cls(["NSMutableArray", "NSArray", "NSObject"])
pfarray_class = cls(["_PFArray", "NSArray", "NSObject"])
shared_key_dict_class = cls(["NSSharedKeyDictionary", "NSMutableDictionary", "NSDictionary", "NSObject"])
shared_key_set_class = cls(["NSSharedKeySet", "NSObject"])
cs_localized_string_class = cls(["CSLocalizedString", "NSString", "NSObject"])
ns_localized_string_class = cls(["__NSLocalizedString", "NSMutableString", "NSString", "NSObject"])
