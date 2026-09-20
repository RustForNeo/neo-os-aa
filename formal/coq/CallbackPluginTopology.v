(*
  NeoOS formal verification -- callback ABI, witness scope and plugin cleanup.

  This is a deliberately small correspondence model of the concrete AA
  boundary.  It does not model NeoVM dispatch, cryptography, witness-rule
  evaluation or arbitrary contract storage.  Instead it makes the protocol
  obligations that the C# code exposes explicit and proves them without
  assumptions: the hook callback tuple is fixed, the success path has the
  required order, a signer scope is bound to the target, and a failed plugin
  cleanup cannot rotate the module pointer.

  Concrete correspondence points:
    contracts/UnifiedSmartWallet.Execution.cs
    contracts/UnifiedSmartWallet.Models.cs
    contracts/UnifiedSmartWallet.VerifyContext.cs
    contracts/hooks/MultiHook.cs
    contracts/verifiers/MultiSigVerifier.cs
    contracts/verifiers/VerifierPayload.cs

  The byte/string fields below are abstract atoms.  Their equality is the
  equality supplied by the NeoVM/serialization layer; this file intentionally
  does not claim to prove that layer.
*)
From Coq Require Import List Bool PeanoNat Lia.
Import ListNotations.

Inductive Field : Type :=
| FTarget : nat -> Field
| FMethod : nat -> Field
| FArgs : list nat -> Field
| FNonce : nat -> Field
| FDeadline : nat -> Field
| FSignature : nat -> Field.

Record Operation : Type := mkOperation {
  target : nat;
  method : nat;
  args : list nat;
  nonce : nat;
  deadline : nat;
  signature : nat
}.

(* This is the exact six-field tuple passed to hooks by BuildHookOperationParams. *)
Definition hook_tuple (op : Operation) : list Field :=
  [FTarget (target op); FMethod (method op); FArgs (args op);
   FNonce (nonce op); FDeadline (deadline op); FSignature (signature op)].

Fixpoint nat_list_eqb (left right : list nat) : bool :=
  match left, right with
  | [], [] => true
  | x :: xs, y :: ys => Nat.eqb x y && nat_list_eqb xs ys
  | _, _ => false
  end.

Definition callback_shape (params : list Field) (op : Operation) : bool :=
  match params with
  | [FTarget t; FMethod m; FArgs a; FNonce n; FDeadline d; FSignature s] =>
      Nat.eqb t (target op) && Nat.eqb m (method op) &&
      nat_list_eqb a (args op) && Nat.eqb n (nonce op) &&
      Nat.eqb d (deadline op) && Nat.eqb s (signature op)
  | _ => false
  end.

Definition callback_positions (params : list Field) : bool :=
  match params with
  | FTarget _ :: FMethod _ :: FArgs _ :: FNonce _ :: FDeadline _ :: FSignature _ :: [] => true
  | _ => false
  end.

Inductive Phase : Type :=
| Validate | PreHook | TargetCall | PostHook | Emit.

Definition success_trace (authorized well_shaped pre_ok target_ok post_ok : bool)
    : list Phase :=
  if authorized && well_shaped && pre_ok && target_ok && post_ok
  then [Validate; PreHook; TargetCall; PostHook; Emit]
  else [].

Definition callback_trace (authorized well_shaped pre_ok target_ok post_ok : bool)
    : list Phase :=
  if authorized && well_shaped && pre_ok && target_ok && post_ok
  then [PreHook; TargetCall; PostHook]
  else [].

Inductive Scope : Type :=
| CalledByEntry
| Custom
| Global.

Definition scope_allows (scope : Scope) (entry target : nat) (allowed : list nat) : bool :=
  match scope with
  | CalledByEntry => Nat.eqb entry target
  | Custom => existsb (Nat.eqb target) allowed
  | Global => true
  end.

Record PluginState : Type := mkPluginState {
  plugin_pointer : nat;
  plugin_storage : nat
}.

Definition cleanup_and_rotate (old new : PluginState) (cleanup_ok : bool) : PluginState :=
  if cleanup_ok
  then mkPluginState (plugin_pointer new) 0
  else old.

Lemma nat_list_eqb_eq :
  forall left right, nat_list_eqb left right = true -> left = right.
Proof.
  induction left as [|x xs IH]; intros right H.
  - destruct right; [reflexivity | discriminate].
  - destruct right as [|y ys]; [discriminate|].
    simpl in H. apply andb_true_iff in H. destruct H as [Hxy Hrest].
    apply Nat.eqb_eq in Hxy. subst y.
    f_equal. apply IH. exact Hrest.
Qed.

Lemma nat_list_eqb_refl :
  forall values, nat_list_eqb values values = true.
Proof.
  induction values as [|value rest IH]; simpl; auto.
  rewrite Nat.eqb_refl, IH.
  reflexivity.
Qed.

Lemma callback_shape_components :
  forall params op,
    callback_shape params op = true ->
    params = hook_tuple op.
Proof.
  intros params op H.
  unfold callback_shape in H.
  destruct params as [|p0 rest0]; [simpl in H; discriminate|].
  destruct p0 as [t|m|a|n|d|s]; try (simpl in H; discriminate).
  destruct rest0 as [|p1 rest1]; [simpl in H; discriminate|].
  destruct p1 as [t1|m|a1|n1|d1|s1]; try (simpl in H; discriminate).
  destruct rest1 as [|p2 rest2]; [simpl in H; discriminate|].
  destruct p2 as [t2|m2|a|n2|d2|s2]; try (simpl in H; discriminate).
  destruct rest2 as [|p3 rest3]; [simpl in H; discriminate|].
  destruct p3 as [t3|m3|a3|n|d3|s3]; try (simpl in H; discriminate).
  destruct rest3 as [|p4 rest4]; [simpl in H; discriminate|].
  destruct p4 as [t4|m4|a4|n4|d|s4]; try (simpl in H; discriminate).
  destruct rest4 as [|p5 rest5]; [simpl in H; discriminate|].
  destruct p5 as [t5|m5|a5|n5|d5|s]; try discriminate.
  destruct rest5; [| discriminate].
  simpl in H.
  repeat rewrite andb_true_iff in H.
  destruct H as [[[[[Ht Hm] Ha] Hn] Hd] Hs].
  apply Nat.eqb_eq in Ht, Hm, Hn, Hd, Hs.
  apply nat_list_eqb_eq in Ha.
  subst t m a n d s.
  reflexivity.
Qed.

Theorem CPT_001_callback_tuple_is_canonical :
  forall op,
    callback_shape (hook_tuple op) op = true /\
    length (hook_tuple op) = 6 /\
    callback_positions (hook_tuple op) = true.
Proof.
  intros op.
  split.
  + unfold callback_shape.
    simpl.
    repeat rewrite Nat.eqb_refl.
    rewrite nat_list_eqb_refl.
    reflexivity.
  + split; reflexivity.
Qed.

Theorem CPT_002_callback_tuple_preserves_operation_fields :
  forall op params,
    callback_shape params op = true ->
    nth_error params 0 = Some (FTarget (target op)) /\
    nth_error params 1 = Some (FMethod (method op)) /\
    nth_error params 2 = Some (FArgs (args op)) /\
    nth_error params 3 = Some (FNonce (nonce op)) /\
    nth_error params 4 = Some (FDeadline (deadline op)) /\
    nth_error params 5 = Some (FSignature (signature op)).
Proof.
  intros op params H.
  apply callback_shape_components in H. subst params.
  repeat split; reflexivity.
Qed.

Theorem CPT_003_success_trace_is_ordered :
  forall authorized well_shaped pre_ok target_ok post_ok,
    success_trace authorized well_shaped pre_ok target_ok post_ok =
      [Validate; PreHook; TargetCall; PostHook; Emit] ->
    authorized = true /\ well_shaped = true /\ pre_ok = true /\
    target_ok = true /\ post_ok = true.
Proof.
  intros authorized well_shaped pre_ok target_ok post_ok H.
  unfold success_trace in H.
  destruct (authorized && well_shaped && pre_ok && target_ok && post_ok) eqn:E;
    [| discriminate].
  repeat rewrite andb_true_iff in E.
  destruct E as [[[[Ha Hs] Hp] Ht] Ho].
  repeat split; assumption.
Qed.

Theorem CPT_004_callback_trace_is_inner_execution_order :
  forall authorized well_shaped pre_ok target_ok post_ok,
    callback_trace authorized well_shaped pre_ok target_ok post_ok =
      [PreHook; TargetCall; PostHook] ->
    authorized = true /\ well_shaped = true /\ pre_ok = true /\
    target_ok = true /\ post_ok = true.
Proof.
  intros authorized well_shaped pre_ok target_ok post_ok H.
  unfold callback_trace in H.
  destruct (authorized && well_shaped && pre_ok && target_ok && post_ok) eqn:E;
    [| discriminate].
  repeat rewrite andb_true_iff in E.
  destruct E as [[[[Ha Hs] Hp] Ht] Ho].
  repeat split; assumption.
Qed.

Theorem CPT_005_witness_scope_binds_called_by_entry :
  forall entry target allowed,
    scope_allows CalledByEntry entry target allowed = true -> entry = target.
Proof.
  intros entry target allowed H.
  simpl in H.
  apply Nat.eqb_eq.
  exact H.
Qed.

Theorem CPT_006_witness_scope_binds_custom_target :
  forall entry target allowed,
    scope_allows Custom entry target allowed = true -> In target allowed.
Proof.
  intros entry target allowed H.
  simpl in H.
  apply existsb_exists in H.
  destruct H as [id [Hin Heq]].
  apply Nat.eqb_eq in Heq.
  subst id.
  exact Hin.
Qed.

Theorem CPT_007_failed_cleanup_preserves_old_plugin :
  forall old new,
    cleanup_and_rotate old new false = old.
Proof.
  intros old new.
  reflexivity.
Qed.

Theorem CPT_008_successful_cleanup_clears_before_rotation :
  forall old new,
    cleanup_and_rotate old new true =
      mkPluginState (plugin_pointer new) 0.
Proof.
  intros old new.
  reflexivity.
Qed.

Theorem CPT_009_successful_rotation_has_no_old_storage :
  forall old new next,
    cleanup_and_rotate old new true = next ->
    plugin_storage next = 0 /\ plugin_pointer next = plugin_pointer new.
Proof.
  intros old new next H.
  rewrite <- H.
  simpl.
  split; reflexivity.
Qed.

Print Assumptions callback_shape_components.
Print Assumptions nat_list_eqb_eq.
Print Assumptions nat_list_eqb_refl.
Print Assumptions CPT_001_callback_tuple_is_canonical.
Print Assumptions CPT_002_callback_tuple_preserves_operation_fields.
Print Assumptions CPT_003_success_trace_is_ordered.
Print Assumptions CPT_004_callback_trace_is_inner_execution_order.
Print Assumptions CPT_005_witness_scope_binds_called_by_entry.
Print Assumptions CPT_006_witness_scope_binds_custom_target.
Print Assumptions CPT_007_failed_cleanup_preserves_old_plugin.
Print Assumptions CPT_008_successful_cleanup_clears_before_rotation.
Print Assumptions CPT_009_successful_rotation_has_no_old_storage.
