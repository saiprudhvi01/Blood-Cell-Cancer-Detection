import tensorflow as tf
import numpy as np
from PIL import Image
import os

# Load the TensorFlow Lite model
model_path = "model1 (MobileNetV2).tflite"
interpreter = tf.lite.Interpreter(model_path=model_path)
interpreter.allocate_tensors()

# Get input and output details
input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()

print("=== MODEL INVESTIGATION ===")
print(f"Model input shape: {input_details[0]['shape']}")
print(f"Model input type: {input_details[0]['dtype']}")
print(f"Model output shape: {output_details[0]['shape']}")
print(f"Model output type: {output_details[0]['dtype']}")
print(f"Number of output classes: {output_details[0]['shape'][-1]}")

# Test with sample images from each category
def preprocess_image(image_path):
    """Preprocess image for model prediction"""
    image = Image.open(image_path)
    image = image.resize((224, 224))
    if image.mode != 'RGB':
        image = image.convert('RGB')
    image_array = np.array(image, dtype=np.float32)
    image_array = image_array / 255.0
    image_array = np.expand_dims(image_array, axis=0)
    return image_array

def test_prediction(image_path, category_name):
    """Test prediction on a single image"""
    try:
        processed_image = preprocess_image(image_path)
        interpreter.set_tensor(input_details[0]['index'], processed_image)
        interpreter.invoke()
        output = interpreter.get_tensor(output_details[0]['index'])
        
        print(f"\n--- {category_name} ---")
        print(f"Raw output: {output}")
        print(f"Output shape: {output.shape}")
        print(f"Predicted class: {np.argmax(output)}")
        print(f"Confidence: {np.max(output):.4f}")
        print(f"All class probabilities: {output[0]}")
        
        return output[0]
    except Exception as e:
        print(f"Error processing {image_path}: {e}")
        return None

# Test images from each category
test_images = [
    ("Blood cell Cancer [ALL]/Benign/Snap_001 (3).jpg", "Benign"),
    ("Blood cell Cancer [ALL]/[Malignant] Pre-B/Snap_001.jpg", "Malignant Pre-B"),
    ("Blood cell Cancer [ALL]/[Malignant] Pro-B/Snap_001.jpg", "Malignant Pro-B"),
    ("Blood cell Cancer [ALL]/[Malignant] early Pre-B/Snap_001.jpg", "Malignant early Pre-B")
]

print("\n=== TESTING SAMPLE IMAGES ===")
all_outputs = []
for image_path, category_name in test_images:
    if os.path.exists(image_path):
        output = test_prediction(image_path, category_name)
        if output is not None:
            all_outputs.append((category_name, output))
    else:
        print(f"Image not found: {image_path}")

print("\n=== CLASS ANALYSIS ===")
if all_outputs:
    print("Analyzing patterns across different categories...")
    
    # Calculate average predictions for each category type
    benign_outputs = [out for name, out in all_outputs if "Benign" in name]
    malignant_outputs = [out for name, out in all_outputs if "Malignant" in name]
    
    if benign_outputs:
        avg_benign = np.mean(benign_outputs, axis=0)
        print(f"\nAverage Benign predictions: {avg_benign}")
        print(f"Benign most likely class: {np.argmax(avg_benign)}")
    
    if malignant_outputs:
        avg_malignant = np.mean(malignant_outputs, axis=0)
        print(f"\nAverage Malignant predictions: {avg_malignant}")
        print(f"Malignant most likely class: {np.argmax(avg_malignant)}")

print("\n=== POSSIBLE CLASS MAPPINGS ===")
print("Based on the output patterns, the classes might represent:")
print("- Class 0: Early stage/developing malignant")
print("- Class 1: Benign/normal")
print("- Class 2: Advanced malignant")
print("- Class 3: Pre-malignant/early detection")
print("\nThis would explain why some malignant images show different classes!")
