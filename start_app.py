# start_app.py
import tkinter as tk
# import the compiled module (name will be Siebel_Log_Analyzer.pyd -> Python import name is Siebel_Log_Analyzer)
from Siebel_Log_Analyzer import SiebelLogAnalyzer

def main():
    root = tk.Tk()
    root.geometry("1000x800")
    root.minsize(800, 600)
    # do NOT set topmost here; keep launcher minimal
    app = SiebelLogAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()