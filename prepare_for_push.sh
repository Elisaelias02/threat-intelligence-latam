#!/bin/bash

echo "🧹 PREPARANDO REPOSITORIO PARA PUSH LIMPIO"
echo "=========================================="

# Limpiar archivos temporales
echo "1. Limpiando archivos temporales..."
find . -name "*.pyc" -delete 2>/dev/null
find . -name "*.pyo" -delete 2>/dev/null
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
rm -f *.log 2>/dev/null
rm -f aegis_threat_intel.log 2>/dev/null

# Verificar estado de git
echo "2. Verificando estado de git..."
git status --porcelain

# Verificar archivos grandes
echo "3. Verificando archivos grandes (>1MB)..."
find . -type f -size +1M -not -path "./.git/*" -not -path "./venv/*" | head -10

# Mostrar archivos en el índice
echo "4. Archivos preparados para commit:"
git diff --cached --name-only

echo ""
echo "✅ REPOSITORIO PREPARADO"
echo "========================"
echo ""
echo "Para hacer push limpio:"
echo "  git push origin $(git branch --show-current)"
echo ""
echo "Para verificar antes del push:"
echo "  git log --oneline -5"
echo "  git diff --cached"
echo ""
