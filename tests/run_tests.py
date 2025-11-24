# tests/run_tests.py
import sys
import os
import unittest

def main():
    """Ejecuta todos los tests en orden"""
    print("============================================")
    print("   EJECUTANDO TODAS LAS PRUEBAS UNITARIAS   ")
    print("============================================")

    # Lista de módulos de test en el orden a ejecutar
    test_modules = [
        'test_auth',
        'test_crypto',
        'test_asymmetric_crypto',
        'test_user_manager',
        'test_integration'
    ]

    total_tests = 0
    total_failures = 0
    total_errors = 0

    for module in test_modules:
        print(f"--- Ejecutando: {module} ---")
        
        # Cargar y ejecutar el módulo de test
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName(module)

        runner = unittest.TextTestRunner()
        result = runner.run(suite)

        # Acumular resultados
        total_tests += result.testsRun
        total_failures += len(result.failures)
        total_errors += len(result.errors)
    
    # Mostrar resumen final
    print("==================================")
    print("   RESUMEN DE TODAS LAS PRUEBAS   ")
    print("==================================")
    print(f"Total de pruebas ejecutadas: {total_tests}")
    print(f"Pruebas exitosas: {total_tests - total_failures - total_errors}")
    print(f"Fallos: {total_failures}")
    print(f"Errores: {total_errors}")


if __name__ == "__main__":
    main()
