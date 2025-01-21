<?php
include 'db.php';

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function validatePassword($password) {
    return preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{15,}$/', $password);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $firstName = $_POST['firstName'];
    $lastName = $_POST['lastName'];
    $email = $_POST['email'];
    $phone = $_POST['phone'];
    $gender = $_POST['gender'];
    $dob = $_POST['dob'];
    $age = $_POST['age'];
    $password = $_POST['password'];
    $image = $_FILES['image'];

    $errors = [];

    if (!preg_match("/^[a-zA-Z]{2,50}$/", $firstName)) {
        $errors[] = "First name must be between 2 and 50 characters and contain only letters.";
    }
    if (!preg_match("/^[a-zA-Z]{2,50}$/", $lastName)) {
        $errors[] = "Last name must be between 2 and 50 characters and contain only letters.";
    }
    if (!validateEmail($email)) {
        $errors[] = "Invalid email address.";
    }
    if (!preg_match("/^\d{8}$/", $phone)) {
        $errors[] = "Phone number must contain exactly 8 digits.";
    }
    if (empty($gender)) {
        $errors[] = "Gender is required.";
    }
    if (new DateTime($dob) > new DateTime()) {
        $errors[] = "Date of birth cannot be in the future.";
    }
    if (!is_numeric($age)) {
        $errors[] = "Age must be a number.";
    }
    if (!validatePassword($password)) {
        $errors[] = "Password must be at least 15 characters long and include uppercase, lowercase, digits, and special characters.";
    }

    if ($image['error'] == 0) {
        $allowedTypes = ['image/jpeg', 'image/png'];
        $maxSize = 5 * 1024 * 1024; // 5MB
        if (!in_array($image['type'], $allowedTypes)) {
            $errors[] = "Only .jpg, .jpeg, and .png images are allowed.";
        }
        if ($image['size'] > $maxSize) {
            $errors[] = "Image size cannot exceed 5MB.";
        }

        $imagePath = 'uploads/' . uniqid() . '.' . pathinfo($image['name'], PATHINFO_EXTENSION);
        if (!move_uploaded_file($image['tmp_name'], $imagePath)) {
            $errors[] = "Failed to upload image.";
        }
    } else {
        $imagePath = null;
    }

    if (empty($errors)) {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $pdo->prepare("INSERT INTO users (first_name, last_name, email, phone, gender, dob, age, password, image_path)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$firstName, $lastName, $email, $phone, $gender, $dob, $age, $hashedPassword, $imagePath]);

        echo "Data submitted successfully!";
    } else {
        foreach ($errors as $error) {
            echo "<p>$error</p>";
        }
    }
}
?>
