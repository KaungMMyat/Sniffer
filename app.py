import flet as ft
from capture.interfaces import get_interfaces

def main(page: ft.Page):
    
    page.title = "Python Packet Sniffer"
    
    page.window.width = 900
    page.window.height = 600
    page.padding = 20
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    
    def start_capture(e):
        print("Starting packet capture...")
        
    def stop_capture(e):
        print("Stopping packet capture...")
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    interfaces = get_interfaces()
    

    
    title = ft.Text(
        "Python Packet Sniffer",
        size = 30,
    )
    
    subtitle = ft.Text(
        "Live Network Traffic Monitor",
        size = 16
    )
    
    interface_dropdown = ft.Dropdown(
        label = "Select Network Interface",
        options = [
            ft.dropdown.Option(interface)   # list comprehension.
            for interface in interfaces
        ],
        width = 300
    )
    
    start_button = ft.Button(
        "Start Capture",
        on_click = start_capture
    )
    
    stop_button = ft.Button(
        "Stop Capture",
        on_click = stop_capture          
    )
    
    page.add(
        ft.Column(
            controls = [
                title,
                subtitle,
                interface_dropdown,
                
                ft.Row(
                    controls = [
                        start_button,
                        stop_button
                    ],
                    spacing = 20, 
                    alignment = ft.MainAxisAlignment.CENTER                   

                ),
                
                ft.Divider(),
            ],
            horizontal_alignment = ft.CrossAxisAlignment.CENTER,
            expand = True

        )
    )           
ft.app(target=main)