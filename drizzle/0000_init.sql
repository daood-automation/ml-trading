CREATE TYPE "public"."account_status" AS ENUM('active', 'inactive', 'removed');--> statement-breakpoint
CREATE TYPE "public"."delivery_type" AS ENUM('direct_to_customer', 'reseller_self_order', 'reseller_collection');--> statement-breakpoint
CREATE TYPE "public"."fulfilment_status" AS ENUM('not_released', 'ready_to_pack', 'packed', 'dispatched', 'delivered', 'collected', 'issue_hold', 'cancelled');--> statement-breakpoint
CREATE TYPE "public"."payment_method" AS ENUM('bank_transfer', 'other_bank', 'cash', 'none');--> statement-breakpoint
CREATE TYPE "public"."payment_status" AS ENUM('awaiting_payment', 'review_pending', 'cash_pending', 'partial_verified', 'full_verified', 'not_found', 'needs_clarification', 'cancelled');--> statement-breakpoint
CREATE TYPE "public"."product_status" AS ENUM('available', 'out_of_stock', 'inactive');--> statement-breakpoint
CREATE TYPE "public"."qbo_status" AS ENUM('not_ready', 'pending', 'recorded');--> statement-breakpoint
CREATE TYPE "public"."user_role" AS ENUM('owner', 'finance_manager', 'finance_team', 'shipping_manager', 'shipping_team', 'reseller');--> statement-breakpoint
CREATE TABLE "audit_log" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid,
	"user_email" varchar(255),
	"user_role" "user_role",
	"action" varchar(64) NOT NULL,
	"order_id" uuid,
	"old_value" text,
	"new_value" text,
	"notes" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "fulfilment" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"order_id" uuid NOT NULL,
	"status" "fulfilment_status" DEFAULT 'not_released' NOT NULL,
	"previous_status" "fulfilment_status",
	"released_by" uuid,
	"released_at" timestamp with time zone,
	"packed_by" uuid,
	"packed_at" timestamp with time zone,
	"dispatched_by" uuid,
	"dispatched_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"courier" varchar(128),
	"shipping_service" varchar(128),
	"tracking_number" varchar(128),
	"received_by" varchar(255),
	"confirmation_source" varchar(255),
	"proof_url" text,
	"issue_type" varchar(128),
	"issue_notes" text,
	"notes" text
);
--> statement-breakpoint
CREATE TABLE "order_items" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"order_id" uuid NOT NULL,
	"line_no" integer NOT NULL,
	"product_code" varchar(64) NOT NULL,
	"product_name" varchar(255) NOT NULL,
	"category" varchar(128),
	"qty" integer NOT NULL,
	"unit_price" numeric(12, 2) NOT NULL,
	"line_total" numeric(12, 2) NOT NULL
);
--> statement-breakpoint
CREATE TABLE "orders" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"order_no" varchar(32) NOT NULL,
	"client_request_id" varchar(128),
	"reseller_id" uuid NOT NULL,
	"delivery_type" "delivery_type" NOT NULL,
	"customer_name" varchar(255) NOT NULL,
	"customer_phone" varchar(64) NOT NULL,
	"customer_email" varchar(255),
	"delivery_address" text NOT NULL,
	"order_total" numeric(12, 2) DEFAULT '0' NOT NULL,
	"amount_claimed" numeric(12, 2) DEFAULT '0' NOT NULL,
	"amount_verified" numeric(12, 2) DEFAULT '0' NOT NULL,
	"payment_method" "payment_method" DEFAULT 'none' NOT NULL,
	"payment_status" "payment_status" DEFAULT 'awaiting_payment' NOT NULL,
	"fulfilment_status" "fulfilment_status" DEFAULT 'not_released' NOT NULL,
	"qbo_status" "qbo_status" DEFAULT 'not_ready' NOT NULL,
	"notes" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "password_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"purpose" varchar(32) NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "payments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"order_id" uuid NOT NULL,
	"method" "payment_method" NOT NULL,
	"amount_claimed" numeric(12, 2) DEFAULT '0' NOT NULL,
	"amount_verified" numeric(12, 2) DEFAULT '0' NOT NULL,
	"result" "payment_status" NOT NULL,
	"bank_reference" varchar(255),
	"proof_key" text,
	"reviewed_by" uuid,
	"reviewed_at" timestamp with time zone,
	"notes" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "products" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"code" varchar(64) NOT NULL,
	"name" varchar(255) NOT NULL,
	"category" varchar(128),
	"status" "product_status" DEFAULT 'available' NOT NULL,
	"qbo_item_name" varchar(255),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "resellers" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" varchar(255) NOT NULL,
	"email" varchar(255) NOT NULL,
	"phone" varchar(64),
	"address" text,
	"status" "account_status" DEFAULT 'active' NOT NULL,
	"receive_status_emails" boolean DEFAULT false NOT NULL,
	"notes" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"token" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" varchar(255) NOT NULL,
	"name" varchar(255) NOT NULL,
	"role" "user_role" NOT NULL,
	"status" "account_status" DEFAULT 'active' NOT NULL,
	"password_hash" text,
	"force_password_setup" boolean DEFAULT true NOT NULL,
	"failed_attempts" integer DEFAULT 0 NOT NULL,
	"locked_until" timestamp with time zone,
	"reseller_id" uuid,
	"last_login_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "fulfilment" ADD CONSTRAINT "fulfilment_order_id_orders_id_fk" FOREIGN KEY ("order_id") REFERENCES "public"."orders"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "fulfilment" ADD CONSTRAINT "fulfilment_released_by_users_id_fk" FOREIGN KEY ("released_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "fulfilment" ADD CONSTRAINT "fulfilment_packed_by_users_id_fk" FOREIGN KEY ("packed_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "fulfilment" ADD CONSTRAINT "fulfilment_dispatched_by_users_id_fk" FOREIGN KEY ("dispatched_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "order_items" ADD CONSTRAINT "order_items_order_id_orders_id_fk" FOREIGN KEY ("order_id") REFERENCES "public"."orders"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "orders" ADD CONSTRAINT "orders_reseller_id_resellers_id_fk" FOREIGN KEY ("reseller_id") REFERENCES "public"."resellers"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "password_tokens" ADD CONSTRAINT "password_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payments" ADD CONSTRAINT "payments_order_id_orders_id_fk" FOREIGN KEY ("order_id") REFERENCES "public"."orders"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payments" ADD CONSTRAINT "payments_reviewed_by_users_id_fk" FOREIGN KEY ("reviewed_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_log_created_at_idx" ON "audit_log" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "audit_log_order_idx" ON "audit_log" USING btree ("order_id");--> statement-breakpoint
CREATE UNIQUE INDEX "fulfilment_order_unique" ON "fulfilment" USING btree ("order_id");--> statement-breakpoint
CREATE INDEX "order_items_order_idx" ON "order_items" USING btree ("order_id");--> statement-breakpoint
CREATE UNIQUE INDEX "orders_order_no_unique" ON "orders" USING btree ("order_no");--> statement-breakpoint
CREATE INDEX "orders_client_req_idx" ON "orders" USING btree ("client_request_id");--> statement-breakpoint
CREATE INDEX "orders_reseller_idx" ON "orders" USING btree ("reseller_id");--> statement-breakpoint
CREATE INDEX "orders_payment_status_idx" ON "orders" USING btree ("payment_status");--> statement-breakpoint
CREATE INDEX "orders_fulfilment_status_idx" ON "orders" USING btree ("fulfilment_status");--> statement-breakpoint
CREATE INDEX "orders_created_at_idx" ON "orders" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "password_tokens_hash_idx" ON "password_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "payments_order_idx" ON "payments" USING btree ("order_id");--> statement-breakpoint
CREATE UNIQUE INDEX "products_code_unique" ON "products" USING btree ("code");--> statement-breakpoint
CREATE INDEX "products_status_idx" ON "products" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "resellers_email_unique" ON "resellers" USING btree ("email");--> statement-breakpoint
CREATE UNIQUE INDEX "sessions_token_unique" ON "sessions" USING btree ("token");--> statement-breakpoint
CREATE INDEX "sessions_user_idx" ON "sessions" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_unique" ON "users" USING btree ("email");--> statement-breakpoint
CREATE INDEX "users_role_idx" ON "users" USING btree ("role");