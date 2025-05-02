from pywinauto import Application

import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="pywinauto")

# Connect to Calculator
app = Application(backend="win32").connect(path="calc.exe")
calc = app.window(title="Calculator")
for ctrl in calc.children():
    print(ctrl)
    if ctrl.friendly_class_name() == "Static":
        text = ctrl.window_text()
        if text.strip():
            print("Found result:", text)
