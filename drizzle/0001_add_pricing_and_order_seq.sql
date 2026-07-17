CREATE SEQUENCE "public"."order_no_seq" INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 START WITH 1 CACHE 1;--> statement-breakpoint
ALTER TABLE "orders" ALTER COLUMN "order_no" SET DEFAULT 'ORD-' || lpad(nextval('order_no_seq')::text, 5, '0');--> statement-breakpoint
ALTER TABLE "products" ADD COLUMN "price" numeric(12, 2);