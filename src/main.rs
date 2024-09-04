use axum::{
    routing::{get, post},
    Router,
    response::{Html, IntoResponse},
    extract::{Form, State},
    http::StatusCode,
};
use dashmap::DashMap;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use validator::{Validate, ValidationError, ValidationErrors, ValidationErrorsKind};
use rust_decimal::Decimal;
use uuid::Uuid;

#[derive(Deserialize, Validate)]
struct User {
    #[validate(length(min = 3, max = 50))]
    username: String,
    #[validate(email)]
    email: String,
    #[validate(custom(function = "validate_password"))]
    password: String,
}

fn validate_password(password: &str) -> Result<(), ValidationError> {
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));
    let has_special = password.chars().any(|c| r#"!@#$%^&*(),.?":{}|<>"#.contains(c));
    let is_long_enough = password.len() >= 10;

    if has_uppercase && has_lowercase && has_digit && has_special && is_long_enough {
        Ok(())
    } else {
        Err(ValidationError::new("Password does not meet complexity requirements"))
    }
}

async fn register_form() -> Html<&'static str> {
    Html(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>User Registration</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }
                form { display: flex; flex-direction: column; }
                input { margin-bottom: 10px; padding: 5px; }
                button { padding: 10px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
                button:hover { background-color: #45a049; }
            </style>
        </head>
        <body>
            <h1>User Registration</h1>
            <form action="/register" method="post">
                <input type="text" name="username" placeholder="Username" required>
                <input type="email" name="email" placeholder="Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Register</button>
            </form>
        </body>
        </html>
        "#
    )
}

async fn register_user(Form(user): Form<User>) -> (StatusCode, Html<String>) {
    match user.validate() {
        Ok(_) => (
            StatusCode::OK,
            Html(format!("<h1>Registration Successful</h1><p>Welcome, {}!</p>", user.username))
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Html(format!("<h1>Registration Failed</h1><p>Errors: {:?}</p>", e))
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_user() {
        let user = User {
            username: "validuser".to_string(),
            email: "user@example.com".to_string(),
            password: "P@ssw0rd123!".to_string(),
        };
        assert!(user.validate().is_ok());
    }

    #[test]
    fn test_invalid_username_too_short() {
        let user = User {
            username: "ab".to_string(), // Too short, min is 3 characters
            email: "user@example.com".to_string(),
            password: "P@ssw0rd123!".to_string(),
        };
        assert!(user.validate().is_err());
    }

    #[test]
    fn test_invalid_username_too_long() {
        let user = User {
            username: "a".repeat(51), // Too long, max is 50 characters
            email: "user@example.com".to_string(),
            password: "P@ssw0rd123!".to_string(),
        };
        assert!(user.validate().is_err());
    }

    #[test]
    fn test_invalid_email_format() {
        let user = User {
            username: "validuser".to_string(),
            email: "not-an-email".to_string(), // Invalid email format
            password: "P@ssw0rd123!".to_string(),
        };
        assert!(user.validate().is_err());
    }

    #[test]
    fn test_invalid_password_no_uppercase() {
        let user = User {
            username: "validuser".to_string(),
            email: "user@example.com".to_string(),
            password: "p@ssw0rd123!".to_string(), // Missing an uppercase letter
        };
        assert!(user.validate().is_err());
    }

    #[test]
    fn test_invalid_password_no_lowercase() {
        let user = User {
            username: "validuser".to_string(),
            email: "user@example.com".to_string(),
            password: "P@SSW0RD123!".to_string(), // Missing a lowercase letter
        };
        assert!(user.validate().is_err());
    }

    #[test]
    fn test_invalid_password_no_digit() {
        let user = User {
            username: "validuser".to_string(),
            email: "user@example.com".to_string(),
            password: "P@ssword!".to_string(), // Missing a digit
        };
        assert!(user.validate().is_err());
    }

    #[test]
    fn test_invalid_password_no_special_character() {
        let user = User {
            username: "validuser".to_string(),
            email: "user@example.com".to_string(),
            password: "Passw0rd123".to_string(), // Missing a special character
        };
        assert!(user.validate().is_err());
    }

    #[test]
    fn test_invalid_password_too_short() {
        let user = User {
            username: "validuser".to_string(),
            email: "user@example.com".to_string(),
            password: "P@ss1".to_string(), // Too short, minimum is 10 characters
        };
        assert!(user.validate().is_err());
    }
}

// fn main() {
//     let user = User {
//         username: "validuser".to_string(),
//         email: "user@example.com".to_string(),
//         password: "P@ssw0rd123!".to_string(),
//     };
//
//     match user.validate() {
//         Ok(_) => println!("User is valid and ready for registration."),
//         Err(e) => println!("User validation failed: {:?}", e),
//     }
//
//     // Simulating invalid user data
//     let invalid_user = User {
//         username: "ab".to_string(), // Too short
//         email: "invalid-email".to_string(), // Invalid email format
//         password: "weakpassword".to_string(), // Does not meet password complexity
//     };
//
//     match invalid_user.validate() {
//         Ok(_) => println!("Invalid user is somehow valid (this should not happen)."),
//         Err(e) => println!("Invalid user validation correctly failed: {:?}", e),
//     }
// }

#[derive(Clone)]
struct Database {
    balances: Arc<DashMap<String, Decimal>>,
    daily_totals: Arc<DashMap<String, Decimal>>,
}

impl Database {
    fn new() -> Self {
        Self {
            balances: Arc::new(DashMap::new()),
            daily_totals: Arc::new(DashMap::new()),
        }
    }

    async fn get_user_balance(&self, user_id: &str) -> Result<Decimal, ValidationError> {
        self.balances.get(user_id)
            .map(|balance| *balance)
            .ok_or_else(|| ValidationError::new("User not found"))
    }

    async fn get_user_daily_transaction_total(&self, user_id: &str) -> Result<Decimal, ValidationError> {
        Ok(*self.daily_totals.entry(user_id.to_string()).or_insert(Decimal::new(0, 0)))
    }

    async fn update_balance(&self, user_id: &str, amount: Decimal) {
        self.balances.entry(user_id.to_string())
            .and_modify(|balance| *balance += amount)
            .or_insert(amount);
    }

    async fn update_daily_total(&self, user_id: &str, amount: Decimal) {
        self.daily_totals.entry(user_id.to_string())
            .and_modify(|total| *total += amount)
            .or_insert(amount);
    }
}

#[derive(Debug, Deserialize, Validate)]
struct Transaction {
    #[validate(custom(function = "validate_uuid"))]
    from_user_id: String,
    #[validate(custom(function = "validate_uuid"))]
    to_user_id: String,
    #[validate(custom(function = "validate_amount"))]
    amount: Decimal,
    #[validate(length(max = 200))]
    description: Option<String>,
}

fn validate_amount(amount: &Decimal) -> Result<(), ValidationError> {
    if *amount >= Decimal::new(1, 2) && *amount <= Decimal::new(1_000_000, 0) {
        Ok(())
    } else {
        Err(ValidationError::new("Amount must be between 0.01 and 1,000,000.00"))
    }
}

fn validate_uuid(uuid: &str) -> Result<(), ValidationError> {
    match Uuid::parse_str(uuid) {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError::new("Invalid UUID")),
    }
}

impl Transaction {
    async fn validate_balance(&self, db: &Database) -> Result<(), ValidationError> {
        let balance = db.get_user_balance(&self.from_user_id).await?;
        if balance < self.amount {
            return Err(ValidationError::new("Insufficient funds"));
        }
        Ok(())
    }

    async fn validate_daily_limit(&self, db: &Database) -> Result<(), ValidationError> {
        let daily_total = db.get_user_daily_transaction_total(&self.from_user_id).await?;
        if daily_total + self.amount > Decimal::new(50000, 0) { // 50,000 daily limit
            return Err(ValidationError::new("Daily transaction limit exceeded"));
        }
        Ok(())
    }

    async fn validate_transaction(&self, db: &Database) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        if let Err(e) = self.validate() {
            for (field, error_kind) in e.into_errors() {
                match error_kind {
                    ValidationErrorsKind::Field(field_errors) => {
                        for error in field_errors {
                            errors.add(field, error);
                        }
                    },
                    ValidationErrorsKind::Struct(_) => {}, // Ignore struct errors for now
                    ValidationErrorsKind::List(_) => {}, // Ignore list errors for now
                }
            }
        }

        if let Err(e) = self.validate_balance(db).await {
            errors.add("amount", e);
        }

        if let Err(e) = self.validate_daily_limit(db).await {
            errors.add("amount", e);
        }

        if self.from_user_id == self.to_user_id {
            errors.add("to_user_id", ValidationError::new("Cannot transfer to the same account"));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    async fn process(&self, db: &Database) -> Result<(), ValidationError> {
        db.update_balance(&self.from_user_id, -self.amount).await;
        db.update_balance(&self.to_user_id, self.amount).await;
        db.update_daily_total(&self.from_user_id, self.amount).await;
        Ok(())
    }
}

async fn transaction_form() -> Html<&'static str> {
    Html(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>RustPay - New Transaction</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }
                form { display: flex; flex-direction: column; }
                input, select { margin-bottom: 10px; padding: 5px; }
                button { padding: 10px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
                button:hover { background-color: #45a049; }
            </style>
        </head>
        <body>
            <h1>RustPay - New Transaction</h1>
            <form action="/transaction" method="post">
                <input type="text" name="from_user_id" placeholder="From User ID (UUID)" required>
                <input type="text" name="to_user_id" placeholder="To User ID (UUID)" required>
                <input type="number" name="amount" step="0.01" min="0.01" max="1000000" placeholder="Amount" required>
                <input type="text" name="description" placeholder="Description (optional)">
                <button type="submit">Submit Transaction</button>
            </form>
        </body>
        </html>
        "#
    )
}

async fn process_transaction(
    State(db): State<Database>,
    Form(transaction): Form<Transaction>,
) -> impl IntoResponse {
    match transaction.validate_transaction(&db).await {
        Ok(_) => {
            match transaction.process(&db).await {
                Ok(_) => (
                    StatusCode::OK,
                    Html(format!("<h1>Transaction Successful</h1><p>Amount: {}</p>", transaction.amount))
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html(format!("<h1>Transaction Failed</h1><p>Error: {:?}</p>", e))
                ),
            }
        },
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Html(format!("<h1>Transaction Failed</h1><p>Errors: {:?}</p>", e))
        ),
    }
}

async fn add_balance(State(db): State<Database>) -> (StatusCode, Html<String>) {
    let user_id = Uuid::new_v4().to_string();
    db.update_balance(&user_id, Decimal::new(100000, 0)).await; // Add 100,000 to the new account
    (StatusCode::OK, Html(format!("Added balance to new user. ID: {}", user_id)))
}

#[tokio::main]
async fn main() {
    let db = Database::new();

    let app = Router::new()
        .route("/", get(register_form))
        .route("/register", post(register_user))
        .route("/transaction", get(transaction_form).post(process_transaction))
        .route("/add_balance", get(add_balance))
        .with_state(db);

    let addr = SocketAddr::from(([0, 0, 0, 0], 9009));
    println!("Server running on http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
