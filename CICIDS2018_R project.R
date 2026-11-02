# ============================================================
# CICIDS2018 DATA PROCESSING AND HYBRID INTRUSION DETECTION
# Python notebook converted to R
# ============================================================

# -----------------------------
# 0. Install and load packages
# -----------------------------
required_packages <- c(
  "readr", "dplyr", "tidyr", "stringr", "caret",
  "randomForest", "xgboost", "ggplot2", "pROC",
  "SHAPforxgboost", "Matrix", "scales"
)

missing_packages <- required_packages[
  !vapply(required_packages, requireNamespace, logical(1), quietly = TRUE)
]
if (length(missing_packages) > 0) {
  install.packages(missing_packages, dependencies = TRUE)
}

suppressPackageStartupMessages({
  library(readr)
  library(dplyr)
  library(tidyr)
  library(stringr)
  library(caret)
  library(randomForest)
  library(xgboost)
  library(ggplot2)
  library(pROC)
  library(SHAPforxgboost)
  library(Matrix)
  library(scales)
})

set.seed(42)

# -----------------------------
# 1. Load dataset
# -----------------------------
# Put 02-14-2018.csv in your working directory, or change this path.
network_data_d1 <- read_csv(
  "C:/Users/Owner/Downloads/02-14-2018.csv/02-14-2018.csv",
  show_col_types = FALSE,
  guess_max = 100000
)

# Remove leading/trailing whitespace from column names
names(network_data_d1) <- trimws(names(network_data_d1))

cat("Initial dimensions:", dim(network_data_d1), "\n")
print(names(network_data_d1))

# -----------------------------
# 2. Fix data types
# -----------------------------
# The original notebook explicitly casts these columns. In R, using
# suppressWarnings(as.numeric()) also handles numeric columns imported
# as character because of malformed/header rows.
integer_columns <- c(
  "Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts",
  "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
  "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Bwd Pkt Len Max",
  "Bwd Pkt Len Min", "Flow IAT Max", "Flow IAT Min",
  "Fwd IAT Tot", "Fwd IAT Max", "Fwd IAT Min",
  "Bwd IAT Tot", "Bwd IAT Max", "Bwd IAT Min",
  "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags",
  "Bwd URG Flags", "Fwd Header Len", "Bwd Header Len",
  "Pkt Len Min", "Pkt Len Max", "FIN Flag Cnt", "SYN Flag Cnt",
  "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt",
  "CWE Flag Count", "ECE Flag Cnt", "Down/Up Ratio",
  "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg",
  "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg",
  "Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts",
  "Subflow Bwd Byts", "Init Fwd Win Byts", "Init Bwd Win Byts",
  "Fwd Act Data Pkts", "Fwd Seg Size Min", "Active Max",
  "Active Min", "Idle Max", "Idle Min"
)

numeric_columns <- c(
  "Fwd Pkt Len Mean", "Fwd Pkt Len Std", "Bwd Pkt Len Mean",
  "Bwd Pkt Len Std", "Flow Byts/s", "Flow Pkts/s",
  "Flow IAT Mean", "Flow IAT Std", "Fwd IAT Mean",
  "Fwd IAT Std", "Bwd IAT Mean", "Bwd IAT Std",
  "Fwd Pkts/s", "Bwd Pkts/s", "Pkt Len Mean", "Pkt Len Std",
  "Pkt Len Var", "Pkt Size Avg", "Fwd Seg Size Avg",
  "Bwd Seg Size Avg", "Active Mean", "Active Std",
  "Idle Mean", "Idle Std"
)

fix_data_type <- function(data) {
  if ("Dst Port" %in% names(data)) {
    data <- data %>% filter(as.character(`Dst Port`) != "Dst Port")
  }

  for (column in intersect(integer_columns, names(data))) {
    data[[column]] <- suppressWarnings(as.numeric(as.character(data[[column]])))
  }
  for (column in intersect(numeric_columns, names(data))) {
    data[[column]] <- suppressWarnings(as.numeric(as.character(data[[column]])))
  }

  data
}

network_data_d1 <- fix_data_type(network_data_d1)

# -----------------------------
# 3. Create behavioral features
# -----------------------------
# SAFE graph-like behavioral features from the original notebook.
if (all(c("Flow Byts/s", "Flow IAT Std") %in% names(network_data_d1))) {
  network_data_d1$Flow_Intensity <-
    network_data_d1[["Flow Byts/s"]] /
    (network_data_d1[["Flow IAT Std"]] + 1)
}

if (all(c("Pkt Len Std", "Pkt Len Var") %in% names(network_data_d1))) {
  network_data_d1$Packet_Variation <-
    network_data_d1[["Pkt Len Std"]] /
    (network_data_d1[["Pkt Len Var"]] + 1)
}

if (all(c("Active Max", "Idle Std") %in% names(network_data_d1))) {
  network_data_d1$Activity_Ratio <-
    network_data_d1[["Active Max"]] /
    (network_data_d1[["Idle Std"]] + 1)
}

# -----------------------------
# 4. Remove infinite and null values
# -----------------------------
drop_infinite_null <- function(data) {
  cat("Before cleaning:", dim(data), "\n")

  # Convert common text representations of infinity to numeric infinity.
  for (column in names(data)) {
    if (is.character(data[[column]])) {
      data[[column]][
        tolower(data[[column]]) %in% c("infinity", "inf", "-infinity", "-inf")
      ] <- NA_character_
    }
  }

  # Convert numeric infinities to NA.
  numeric_cols <- names(data)[vapply(data, is.numeric, logical(1))]
  for (column in numeric_cols) {
    data[[column]][!is.finite(data[[column]])] <- NA_real_
  }

  data <- data %>% drop_na()
  cat("After cleaning:", dim(data), "\n")
  data
}

network_data_d1 <- drop_infinite_null(network_data_d1)
cat("Remaining missing values:", sum(is.na(network_data_d1)), "\n")

# -----------------------------
# 5. Drop unnecessary column
# -----------------------------
if ("Timestamp" %in% names(network_data_d1)) {
  network_data_d1 <- network_data_d1 %>% select(-Timestamp)
}
cat("After dropping Timestamp:", dim(network_data_d1), "\n")
print(names(network_data_d1))

# -----------------------------
# 6. Inspect label distribution
# -----------------------------
if ("Label" %in% names(network_data_d1)) {
  print(table(network_data_d1$Label))
} else {
  stop("The dataset does not contain a 'Label' column.")
}

# -----------------------------
# 7. Drop constant columns
# -----------------------------
numeric_cols <- names(network_data_d1)[
  vapply(network_data_d1, is.numeric, logical(1))
]

constant_columns <- numeric_cols[
  vapply(network_data_d1[numeric_cols], function(x) {
    length(unique(x[!is.na(x)])) <= 1
  }, logical(1))
]

cat("Constant columns:", paste(constant_columns, collapse = ", "), "\n")
network_data_d1 <- network_data_d1 %>% select(-all_of(constant_columns))
cat("After removing constant columns:", dim(network_data_d1), "\n")

# -----------------------------
# 8. Check and remove duplicate columns
# -----------------------------
find_duplicate_columns <- function(data) {
  duplicate_names <- character(0)
  column_names <- names(data)

  if (length(column_names) < 2) return(duplicate_names)

  for (i in seq_len(length(column_names) - 1)) {
    for (j in (i + 1):length(column_names)) {
      if (identical(data[[i]], data[[j]])) {
        duplicate_names <- c(duplicate_names, column_names[j])
      }
    }
  }
  unique(duplicate_names)
}

duplicate_columns <- find_duplicate_columns(network_data_d1)
cat("Duplicate columns:", paste(duplicate_columns, collapse = ", "), "\n")
if (length(duplicate_columns) > 0) {
  network_data_d1 <- network_data_d1 %>% select(-all_of(duplicate_columns))
}
cat("New shape:", dim(network_data_d1), "\n")

# -----------------------------
# 9. Encode target label
# -----------------------------
network_data_d1$Label <- as.factor(network_data_d1$Label)
label_levels <- levels(network_data_d1$Label)
label_mapping <- data.frame(
  Attack = label_levels,
  Encoding = seq_along(label_levels) - 1
)
print(label_mapping)

# -----------------------------
# 10. Initial stratified train-test split
# -----------------------------
set.seed(42)
initial_index <- createDataPartition(
  network_data_d1$Label,
  p = 0.80,
  list = FALSE
)

initial_train <- network_data_d1[initial_index, , drop = FALSE]
initial_test  <- network_data_d1[-initial_index, , drop = FALSE]

cat("Initial training rows:", nrow(initial_train), "\n")
cat("Initial testing rows:", nrow(initial_test), "\n")

# -----------------------------
# 11. Standard scaling (optional workflow)
# -----------------------------
# Fit scaling parameters only on training data, then apply to test data.
# This mirrors the notebook's StandardScaler step.
initial_x_train <- initial_train %>% select(-Label)
initial_x_test  <- initial_test %>% select(-Label)

numeric_initial <- names(initial_x_train)[
  vapply(initial_x_train, is.numeric, logical(1))
]

if (length(numeric_initial) > 0) {
  scaling_means <- vapply(initial_x_train[numeric_initial], mean, numeric(1), na.rm = TRUE)
  scaling_sds <- vapply(initial_x_train[numeric_initial], sd, numeric(1), na.rm = TRUE)
  scaling_sds[is.na(scaling_sds) | scaling_sds == 0] <- 1

  initial_x_train[numeric_initial] <- Map(
    function(x, m, s) (x - m) / s,
    initial_x_train[numeric_initial],
    scaling_means,
    scaling_sds
  )
  initial_x_test[numeric_initial] <- Map(
    function(x, m, s) (x - m) / s,
    initial_x_test[numeric_initial],
    scaling_means,
    scaling_sds
  )
}

# -----------------------------
# 12. Save processed dataset
# -----------------------------
write_csv(network_data_d1, "processed_data.csv")
cat("Saved processed_data.csv in:", getwd(), "\n")

# Reload processed dataset, as in the original notebook
df <- read_csv("processed_data.csv", show_col_types = FALSE, guess_max = 100000)
df <- df %>% distinct()
names(df) <- trimws(names(df))
cat("After reload and duplicate-row removal:", dim(df), "\n")

# -----------------------------
# 13. Prepare features and target
# -----------------------------
if ("Timestamp" %in% names(df)) {
  df <- df %>% select(-Timestamp)
}

# Ensure target is categorical before modeling.
df$Label <- as.factor(df$Label)

X_all <- df %>% select(-Label)
y_all <- df$Label

# Convert feature columns to numeric, matching pandas to_numeric(errors="coerce").
X_all <- as.data.frame(lapply(X_all, function(x) {
  suppressWarnings(as.numeric(as.character(x)))
}))
X_all <- as.data.frame(lapply(X_all, function(x) {
  x[!is.finite(x)] <- NA_real_
  x
}))

# Remove rows made incomplete by numeric conversion.
complete_rows <- complete.cases(X_all) & !is.na(y_all)
X_all <- X_all[complete_rows, , drop = FALSE]
y_all <- droplevels(y_all[complete_rows])

cat("Feature shape:", dim(X_all), "\n")
cat("Target distribution:\n")
print(table(y_all))

# -----------------------------
# 14. Random Forest model
# -----------------------------
set.seed(42)
rf_index <- createDataPartition(y_all, p = 0.80, list = FALSE)
X_train_rf <- X_all[rf_index, , drop = FALSE]
X_test_rf  <- X_all[-rf_index, , drop = FALSE]
y_train_rf <- y_all[rf_index]
y_test_rf  <- y_all[-rf_index]

rf_model <- randomForest(
  x = X_train_rf,
  y = y_train_rf,
  ntree = 50,
  maxnodes = 2^10,
  nodesize = 2,
  importance = TRUE
)

rf_predictions <- predict(rf_model, X_test_rf)
cat("Random Forest accuracy:",
    mean(rf_predictions == y_test_rf), "\n")

# Permuted-label experiment from the notebook.
# This is a diagnostic negative-control experiment, not a valid model result.
set.seed(42)
y_train_shuffled <- sample(y_train_rf)
rf_shuffled_model <- randomForest(
  x = X_train_rf,
  y = y_train_shuffled,
  ntree = 50,
  maxnodes = 2^10,
  nodesize = 2
)
rf_shuffled_predictions <- predict(rf_shuffled_model, X_test_rf)
cat("Random Forest accuracy with shuffled training labels:",
    mean(rf_shuffled_predictions == y_test_rf), "\n")

# -----------------------------
# 15. Prepare binary XGBoost dataset
# -----------------------------
# The original notebook removes encoded class 1 and then trains a binary
# classifier. Here we remove the second factor level by its encoded order.
# Check the printed mapping above before interpreting which attack is removed.
if (nlevels(y_all) < 2) {
  stop("At least two target classes are required for XGBoost.")
}

# Reproduce: df = df[df['Label'] != 1]
# Labels in the notebook were LabelEncoder integers (starting at zero).
# The second factor level corresponds to encoded class 1.
if (nlevels(y_all) >= 3) {
  keep_rows <- y_all != levels(y_all)[2]
  X_binary <- X_all[keep_rows, , drop = FALSE]
  y_binary_original <- droplevels(y_all[keep_rows])
} else {
  warning(
    "The target has fewer than 3 classes. The notebook's removal of encoded class 1 ",
    "would leave only one class, so no class was removed."
  )
  X_binary <- X_all
  y_binary_original <- y_all
}

# Encode remaining labels as 0, 1, ... for XGBoost.
y_binary_factor <- droplevels(as.factor(y_binary_original))
binary_levels <- levels(y_binary_factor)
y_binary <- as.integer(y_binary_factor) - 1

cat("XGBoost classes:\n")
print(data.frame(Class = binary_levels, Encoding = seq_along(binary_levels) - 1))
print(table(y_binary))

# -----------------------------
# 16. Remove selected leakage-related columns
# -----------------------------
columns_to_drop <- c(
  "Dst Port",
  "Fwd Seg Size Min",
  "Fwd Act Data Pkts",
  "Fwd Header Len",
  "Flow Bytes/s",
  "Flow Packets/s",
  "Flow Pkts/s",
  "TotLen Fwd Pkts",
  "Bwd Header Len"
)

present_drop_columns <- intersect(columns_to_drop, names(X_binary))
cat("Dropping columns:", paste(present_drop_columns, collapse = ", "), "\n")
X_binary <- X_binary %>% select(-all_of(present_drop_columns))

# Drop zero-variance columns after feature selection.
nzv <- nearZeroVar(X_binary)
if (length(nzv) > 0) {
  X_binary <- X_binary[, -nzv, drop = FALSE]
}

# -----------------------------
# 17. Train-test split for XGBoost
# -----------------------------
set.seed(42)
xgb_index <- createDataPartition(y_binary, p = 0.80, list = FALSE)

X_train <- X_binary[xgb_index, , drop = FALSE]
X_test  <- X_binary[-xgb_index, , drop = FALSE]
y_train <- y_binary[xgb_index]
y_test  <- y_binary[-xgb_index]

cat("X_train:", dim(X_train), "\n")
cat("X_test:", dim(X_test), "\n")
cat("Train/test index overlap:", length(intersect(xgb_index, setdiff(seq_len(nrow(X_binary)), xgb_index))), "\n")

# XGBoost requires numeric matrices.
X_train_matrix <- as.matrix(X_train)
X_test_matrix <- as.matrix(X_test)

dtrain <- xgb.DMatrix(data = X_train_matrix, label = y_train)
dtest  <- xgb.DMatrix(data = X_test_matrix, label = y_test)

# -----------------------------
# 18. Train XGBoost model
# -----------------------------
number_of_classes <- length(unique(y_train))

xgb_params <- list(
  max_depth = 6,
  eta = 0.1,
  subsample = 0.8,
  colsample_bytree = 0.8,
  eval_metric = if (number_of_classes == 2) "logloss" else "mlogloss",
  tree_method = "hist"
)

if (number_of_classes == 2) {
  xgb_params$objective <- "binary:logistic"
} else {
  xgb_params$objective <- "multi:softprob"
  xgb_params$num_class <- number_of_classes
}

set.seed(42)
xgb_model <- xgb.train(
  params = xgb_params,
  data = dtrain,
  nrounds = 100,
  watchlist = list(train = dtrain, test = dtest),
  verbose = 0
)

# -----------------------------
# 19. Model evaluation
# -----------------------------
xgb_raw_predictions <- predict(xgb_model, dtest)

if (number_of_classes == 2) {
  y_prob <- as.numeric(xgb_raw_predictions)
  y_pred <- ifelse(y_prob >= 0.5, 1, 0)
} else {
  probability_matrix <- matrix(
    xgb_raw_predictions,
    ncol = number_of_classes,
    byrow = TRUE
  )
  y_pred <- max.col(probability_matrix) - 1
  y_prob <- probability_matrix[, 2]
}

cat("XGBoost accuracy:", mean(y_pred == y_test), "\n")
cat("\nClassification report:\n")
print(confusionMatrix(
  factor(y_pred, levels = sort(unique(y_test))),
  factor(y_test, levels = sort(unique(y_test)))
))

cat("\nConfusion matrix:\n")
xgb_cm <- table(Actual = y_test, Predicted = y_pred)
print(xgb_cm)

# -----------------------------
# 20. Feature importance
# -----------------------------
importance_table <- xgb.importance(
  feature_names = colnames(X_train_matrix),
  model = xgb_model
)
print(head(importance_table, 10))

if (nrow(importance_table) > 0) {
  importance_plot <- xgb.ggplot.importance(
    importance_matrix = importance_table[1:min(10, nrow(importance_table)), ]
  )
  print(importance_plot)
  ggsave("xgboost_feature_importance.png", importance_plot,
         width = 8, height = 6, dpi = 300)
}

# -----------------------------
# 21. Five-fold cross-validation
# -----------------------------
# xgb.cv uses stratified folds for classification.
set.seed(42)
cv_result <- xgb.cv(
  params = xgb_params,
  data = xgb.DMatrix(as.matrix(X_binary), label = y_binary),
  nrounds = 100,
  nfold = 5,
  stratified = TRUE,
  metrics = if (number_of_classes == 2) "error" else "merror",
  verbose = 0
)
print(cv_result)

# -----------------------------
# 22. ROC-AUC
# -----------------------------
if (number_of_classes == 2) {
  roc_object <- pROC::roc(
    response = y_test,
    predictor = y_prob,
    levels = c(0, 1),
    direction = "<",
    quiet = TRUE
  )
  cat("ROC-AUC:", as.numeric(pROC::auc(roc_object)), "\n")

  roc_plot <- ggroc(roc_object) +
    geom_abline(intercept = 0, slope = 1, linetype = "dashed") +
    labs(
      title = "ROC Curve",
      x = "False Positive Rate",
      y = "True Positive Rate"
    ) +
    theme_minimal()

  print(roc_plot)
  ggsave("roc_curve.png", roc_plot, width = 6, height = 5, dpi = 300)
} else {
  cat("ROC-AUC section skipped: this evaluation has more than two classes.\n")
}

# -----------------------------
# 23. SHAP explainability
# -----------------------------
# SHAPforxgboost supports the binary XGBoost model most directly.
if (number_of_classes == 2) {
  shap_values <- SHAPforxgboost::shap.values(
    xgb_model = xgb_model,
    X_train = X_train_matrix
  )

  shap_long <- SHAPforxgboost::shap.prep(
    shap_contrib = shap_values$shap_score,
    X_train = X_train_matrix
  )

  shap_summary <- SHAPforxgboost::shap.plot.summary(shap_long)
  print(shap_summary)
  ggsave("shap_summary.png", shap_summary, width = 9, height = 7, dpi = 300)

  shap_bar <- SHAPforxgboost::shap.plot.summary(
    shap_long,
    dilute = 1
  )
  print(shap_bar)
  ggsave("shap_bar.png", shap_bar, width = 9, height = 7, dpi = 300)
} else {
  cat("SHAP block skipped: this script's SHAP section is configured for binary XGBoost.\n")
}

# -----------------------------
# 24. Confusion matrix heatmap
# -----------------------------
cm_df <- as.data.frame(xgb_cm)
names(cm_df) <- c("Actual", "Predicted", "Count")

confusion_plot <- ggplot(cm_df, aes(x = Predicted, y = Actual, fill = Count)) +
  geom_tile(color = "white") +
  geom_text(aes(label = Count), size = 5) +
  scale_fill_gradient(low = "white", high = "steelblue") +
  labs(
    title = "Confusion Matrix of XGBoost",
    x = "Predicted Label",
    y = "Actual Label"
  ) +
  theme_minimal()

print(confusion_plot)
ggsave("confusion_matrix.png", confusion_plot, width = 6, height = 5, dpi = 300)

# -----------------------------
# 25. Signature-based detection rules
# -----------------------------
signature_rule <- function(row) {
  # Rule 1: Extremely high traffic rate
  if ("Flow Byts/s" %in% names(row) &&
      !is.na(row[["Flow Byts/s"]]) && row[["Flow Byts/s"]] > 1e6) {
    return(1)
  }

  # Rule 2: Suspicious backward packets
  if ("Tot Bwd Pkts" %in% names(row) &&
      !is.na(row[["Tot Bwd Pkts"]]) && row[["Tot Bwd Pkts"]] > 1000) {
    return(1)
  }

  # Rule 3: Very short duration + high packets
  if (all(c("Flow Duration", "Tot Fwd Pkts") %in% names(row)) &&
      !is.na(row[["Flow Duration"]]) && !is.na(row[["Tot Fwd Pkts"]]) &&
      row[["Flow Duration"]] < 50 && row[["Tot Fwd Pkts"]] > 500) {
    return(1)
  }

  # Rule 4: Abnormal packet rate
  if ("Bwd Pkts/s" %in% names(row) &&
      !is.na(row[["Bwd Pkts/s"]]) && row[["Bwd Pkts/s"]] > 50000) {
    return(1)
  }

  0
}

# Apply signature rules to the same test rows used by XGBoost.
signature_predictions <- apply(X_test, 1, signature_rule)

# Hybrid prediction: signature rule takes priority; otherwise use ML output.
final_pred <- ifelse(signature_predictions == 1, 1, y_pred)

cat("Hybrid accuracy:", mean(final_pred == y_test), "\n")
cat("\nHybrid confusion matrix:\n")
hybrid_cm <- table(Actual = y_test, Predicted = final_pred)
print(hybrid_cm)

cat("\nHybrid classification metrics:\n")
print(confusionMatrix(
  factor(final_pred, levels = sort(unique(y_test))),
  factor(y_test, levels = sort(unique(y_test)))
))

# -----------------------------
# 26. Detection method distribution
# -----------------------------
detection_type <- ifelse(signature_predictions == 1, "Signature", "ML")
detection_counts <- table(detection_type)
print(detection_counts)

total_detections <- length(detection_type)
signature_count <- sum(detection_type == "Signature")
ml_count <- sum(detection_type == "ML")

cat(sprintf(
  "Signature Detection: %d (%.2f%%)\n",
  signature_count, signature_count / total_detections * 100
))
cat(sprintf(
  "ML Detection: %d (%.2f%%)\n",
  ml_count, ml_count / total_detections * 100
))

detection_df <- as.data.frame(detection_counts)
names(detection_df) <- c("Detection_Method", "Count")

detection_plot <- ggplot(
  detection_df,
  aes(x = Detection_Method, y = Count)
) +
  geom_col() +
  labs(
    title = "Detection Method Distribution",
    x = "Detection Method",
    y = "Count"
  ) +
  theme_minimal()

print(detection_plot)
ggsave("detection_method_distribution.png", detection_plot,
       width = 7, height = 5, dpi = 300)

# -----------------------------
# 27. Error analysis plot
# -----------------------------
# For binary labels: 0 = benign, 1 = attack.
if (number_of_classes == 2) {
  TP <- sum(y_test == 1 & final_pred == 1)
  TN <- sum(y_test == 0 & final_pred == 0)
  FP <- sum(y_test == 0 & final_pred == 1)
  FN <- sum(y_test == 1 & final_pred == 0)

  error_df <- data.frame(
    Outcome = c("True Positive", "False Positive",
                "False Negative", "True Negative"),
    Count = c(TP, FP, FN, TN)
  )

  error_plot <- ggplot(error_df, aes(x = Outcome, y = Count)) +
    geom_col() +
    geom_text(aes(label = Count), vjust = -0.3) +
    scale_y_log10() +
    labs(
      title = "Error Analysis of Proposed Hybrid IDS",
      x = "Classification Outcome",
      y = "Count (log scale)"
    ) +
    theme_minimal() +
    theme(axis.text.x = element_text(angle = 20, hjust = 1))

  print(error_plot)
  ggsave("ERROR_ANALYSIS.png", error_plot,
         width = 8, height = 6, dpi = 300)
}

# -----------------------------
# 28. Final checks
# -----------------------------
cat("\nFinal train dimensions:", dim(X_train), "\n")
cat("Final test dimensions:", dim(X_test), "\n")
cat("Number of duplicate rows in processed data:", sum(duplicated(df)), "\n")
cat("Final label distribution:\n")
print(table(df$Label))

cat("\nPipeline completed.\n")
