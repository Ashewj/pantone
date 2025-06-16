import time
from pywinauto import Desktop
import win32gui
import win32con

def clicar_botao_por_handle(texto_botao, timeout=0.5, interval=0.05):
    start_time = time.time()
    while time.time() - start_time < timeout:
        for win in Desktop(backend="win32").windows(title="Confirm"):
            for child in win.children():
                button_text = child.window_text()
                if button_text == texto_botao or button_text == f"&{texto_botao}":
                    try:
                        win32gui.SendMessage(child.handle, win32con.BM_CLICK, 0, 0)
                        win32gui.PostMessage(child.handle, win32con.BM_CLICK, 0, 0)
                        print(f"Clicking button '{button_text}' with handle {child.handle}")
                    except:
                        pass
                    return True
        time.sleep(interval)
    return False

clicar_botao_por_handle("No")