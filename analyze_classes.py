import numpy as np

# Based on the investigation results:
# Class 0: Malignant early Pre-B (early stage cancer)
# Class 1: Malignant Pre-B (developing cancer) 
# Class 2: Malignant Pro-B (advanced cancer)
# Class 3: Benign (no cancer)

print("=== DETAILED CLASS ANALYSIS ===")
print("\nFrom the investigation:")
print("Benign images → Class 3 (99.96% confidence)")
print("Malignant early Pre-B → Class 0 (99.94% confidence)")
print("Malignant Pre-B → Class 1 (99.86% confidence)") 
print("Malignant Pro-B → Class 2 (94.76% confidence)")

print("\n=== MEDICAL INTERPRETATION ===")
print("This model detects different STAGES of blood cancer:")
print("• Class 0: Early Pre-B (Early stage - 'about to grow')")
print("• Class 1: Pre-B (Developing stage)")
print("• Class 2: Pro-B (Advanced stage)")
print("• Class 3: Benign (Healthy)")

print("\n=== RECOMMENDED MAPPING ===")
print("For user interface, we should map:")
print("• Classes 0, 1, 2 → 'Disease Present (YES)'")
print("• Class 3 → 'Disease Absent (NO)'")
print("\nBut we can also provide more detailed information about the stage!")
