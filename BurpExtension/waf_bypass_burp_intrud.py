# waf_bypass_advanced.py
from burp import IBurpExtender, IIntruderPayloadProcessor, ITab
from javax.swing import JPanel, JCheckBox, JLabel, BoxLayout, JTextField
from java.awt import FlowLayout

class BurpExtender(IBurpExtender, IIntruderPayloadProcessor, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("WAF Bypass Advanced")
        callbacks.registerIntruderPayloadProcessor(self)
        
        # Create UI
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        
        # Checkboxes per bypass types
        self.unicode_zwsp = JCheckBox("Unicode ZWSP", True)
        self.unicode_zwnj = JCheckBox("Unicode ZWNJ", True)
        self.unicode_confuse = JCheckBox("Unicode Confusables", True)
        self.sql_comments = JCheckBox("SQL Comments", True)
        self.case_variation = JCheckBox("Case Variations", False)
        self.double_encoding = JCheckBox("Double URL Encoding", True)
        self.path_variants = JCheckBox("Path Traversal Variants", True)
        
        # Aggiungi multiplier
        multiplier_panel = JPanel(FlowLayout())
        multiplier_panel.add(JLabel("Repeat each bypass: "))
        self.multiplier = JTextField("1", 5)
        multiplier_panel.add(self.multiplier)
        
        # Add all to panel
        self.panel.add(JLabel("Select Active Bypasses:"))
        self.panel.add(self.unicode_zwsp)
        self.panel.add(self.unicode_zwnj)
        self.panel.add(self.unicode_confuse)
        self.panel.add(self.sql_comments)
        self.panel.add(self.case_variation)
        self.panel.add(self.double_encoding)
        self.panel.add(self.path_variants)
        self.panel.add(multiplier_panel)
        
        callbacks.addSuiteTab(self)
        
    def getTabCaption(self):
        return "WAF Bypass"
        
    def getUiComponent(self):
        return self.panel
        
    def getProcessorName(self):
        return "WAF Bypass Advanced"
    
    def processPayload(self, currentPayload, originalPayload, baseValue):
        payload_string = self._helpers.bytesToString(currentPayload)
        results = [payload_string]  # Always include original
        
        multiplier = int(self.multiplier.getText())
        
        # Apply selected bypasses
        if self.unicode_zwsp.isSelected():
            for i in range(multiplier):
                variant = self.applyUnicodeZWSP(payload_string)
                if variant != payload_string:
                    results.append(variant)
        
        if self.unicode_confuse.isSelected():
            for i in range(multiplier):
                variant = self.applyConfusables(payload_string)
                if variant != payload_string:
                    results.append(variant)
        
        # ... altri bypass ...
        
        return results
    
    def applyUnicodeZWSP(self, payload):
        # Inserisce ZWSP in parole chiave
        keywords = ['select', 'union', 'from', 'where', 'script', 'admin']
        result = payload
        for keyword in keywords:
            if keyword in result.lower():
                # Inserisci ZWSP nel mezzo della parola
                mid = len(keyword) // 2
                replacement = keyword[:mid] + '\u200b' + keyword[mid:]
                import re
                result = re.sub(keyword, replacement, result, flags=re.IGNORECASE)
        return result
    
    def applyConfusables(self, payload):
        # Sostituisci con caratteri simili
        replacements = {
            'a': '\u03b1',  # Greek alpha
            'e': '\u0435',  # Cyrillic e
            'o': '\u043e',  # Cyrillic o
        }
        result = payload
        for char, replacement in replacements.items():
            result = result.replace(char, replacement)
        return result