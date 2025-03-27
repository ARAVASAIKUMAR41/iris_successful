import cv2
import dlib
import numpy as np
import os
import argparse  # Import the argparse module
import traceback

# Create a directory for storing iris images
dataset_path = "iris_dataset"
os.makedirs(dataset_path, exist_ok=True)

# Load Dlib face detector and shape predictor
detector = dlib.get_frontal_face_detector()
try:
    predictor = dlib.shape_predictor("shape_predictor_68_face_landmarks.dat")
except RuntimeError as e:
    print(f"[ERROR] Could not load shape predictor: {e}.  Make sure 'shape_predictor_68_face_landmarks.dat' is in the correct directory.")
    exit(2)  # Use exit code 2 to indicate failure

def enhance_image(image):
    """Enhance image quality before saving."""
    try:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        equalized = cv2.equalizeHist(blurred)
        return cv2.resize(equalized, (64, 64))
    except Exception as e:
        print(f"[ERROR] Error enhancing image: {e}")
        return None

def extract_iris(image, landmarks):
    """Extract left and right iris from detected face landmarks."""
    try:
        left_eye = landmarks.parts()[36:42]
        right_eye = landmarks.parts()[42:48]

        lx, ly, lw, lh = cv2.boundingRect(np.array([(point.x, point.y) for point in left_eye]))
        rx, ry, rw, rh = cv2.boundingRect(np.array([(point.x, point.y) for point in right_eye]))

        if lw == 0 or lh == 0 or rw == 0 or rh == 0:
            return None, None

        left_iris = enhance_image(image[ly:ly + lh, lx:lx + lw])
        if left_iris is None:
            return None, None

        right_iris = enhance_image(image[ry:ry + rh, rx:rx + rw])
        if right_iris is None:
            return None, None

        return left_iris, right_iris
    except Exception as e:
        print(f"[ERROR] Error extracting iris: {e}")
        return None, None

# --- Argument Parsing ---
parser = argparse.ArgumentParser(description="Capture iris images for user.")
parser.add_argument("--username", required=True, help="Username for the user.")
args = parser.parse_args()

username = args.username  # Get username from command line arguments
# --- End Argument Parsing ---

user_folder = f"{dataset_path}/{username}"
try:
    os.makedirs(user_folder, exist_ok=True)
except Exception as e:
    print(f"[ERROR] Could not create user folder: {e}")
    exit(2)

# Initialize camera
cap = cv2.VideoCapture(0)

if not cap.isOpened():
    print("[ERROR] Could not open camera.  Make sure a camera is connected and accessible.")
    exit(2)

count = 0
total_images = 60  # Store 60 left and 60 right iris images

print("[INFO] Capturing iris images. Look at the camera...")

while count < total_images:
    try:
        ret, frame = cap.read()
        if not ret:
            print("[ERROR] Camera not accessible!")
            break

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = detector(gray)

        for face in faces:
            try:
                landmarks = predictor(gray, face)
                left_iris, right_iris = extract_iris(frame, landmarks)

                if left_iris is None or right_iris is None:
                    print("[WARNING] Could not detect iris. Trying again...")
                    continue

                # Save images in the user's folder
                cv2.imwrite(f"{user_folder}/{username}_left_iris_{count}.jpg", left_iris)
                cv2.imwrite(f"{user_folder}/{username}_right_iris_{count}.jpg", right_iris)
                print(f"[INFO] Captured {count + 1}/{total_images} iris images.")

                count += 1
            except Exception as e:
                print(f"[ERROR] Error processing face: {e}\n{traceback.format_exc()}")

        cv2.imshow("Iris Capture", frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break
    except Exception as e:
        print(f"[ERROR] Error in main loop: {e}\n{traceback.format_exc()}")
        exit(2)

cap.release()
cv2.destroyAllWindows()

print("[INFO] Iris image capturing completed successfully!")
exit(0)  # Exit with code 0 on success