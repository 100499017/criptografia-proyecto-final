# src/user_manager.py
import os
import json

class UserManager:
    def __init__(self):
        self.users_file = 'data/users.json'
    
    def user_exists(self, username: str) -> bool:
        """Verifica si un usuario existe"""
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
            return username in users
        except:
            return False
    
    def list_users(self):
        """Lista todos los usuarios registrados"""
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
            return [user for user in users.keys()]
        except:
            return []
