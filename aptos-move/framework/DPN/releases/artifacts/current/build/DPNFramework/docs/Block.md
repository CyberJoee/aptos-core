
<a name="0x1_Block"></a>

# Module `0x1::Block`

This module defines a struct storing the metadata of the block and new block events.


-  [Resource `BlockMetadata`](#0x1_Block_BlockMetadata)
-  [Struct `NewBlockEvent`](#0x1_Block_NewBlockEvent)
-  [Constants](#@Constants_0)
-  [Function `initialize_block_metadata`](#0x1_Block_initialize_block_metadata)
-  [Function `is_initialized`](#0x1_Block_is_initialized)
-  [Function `block_prologue`](#0x1_Block_block_prologue)
-  [Function `get_current_block_height`](#0x1_Block_get_current_block_height)
-  [Module Specification](#@Module_Specification_1)
    -  [Initialization](#@Initialization_2)


<pre><code><b>use</b> <a href="CoreAddresses.md#0x1_CoreAddresses">0x1::CoreAddresses</a>;
<b>use</b> <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Errors.md#0x1_Errors">0x1::Errors</a>;
<b>use</b> <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Event.md#0x1_Event">0x1::Event</a>;
<b>use</b> <a href="Timestamp.md#0x1_Timestamp">0x1::Timestamp</a>;
<b>use</b> <a href="ValidatorSystem.md#0x1_ValidatorSystem">0x1::ValidatorSystem</a>;
</code></pre>



<a name="0x1_Block_BlockMetadata"></a>

## Resource `BlockMetadata`



<pre><code><b>struct</b> <a href="Block.md#0x1_Block_BlockMetadata">BlockMetadata</a> <b>has</b> key
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>height: u64</code>
</dt>
<dd>
 Height of the current block
</dd>
<dt>
<code>new_block_events: <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Event.md#0x1_Event_EventHandle">Event::EventHandle</a>&lt;<a href="Block.md#0x1_Block_NewBlockEvent">Block::NewBlockEvent</a>&gt;</code>
</dt>
<dd>
 Handle where events with the time of new blocks are emitted
</dd>
</dl>


</details>

<a name="0x1_Block_NewBlockEvent"></a>

## Struct `NewBlockEvent`



<pre><code><b>struct</b> <a href="Block.md#0x1_Block_NewBlockEvent">NewBlockEvent</a> <b>has</b> drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>round: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>proposer: <b>address</b></code>
</dt>
<dd>

</dd>
<dt>
<code>previous_block_votes: vector&lt;<b>address</b>&gt;</code>
</dt>
<dd>

</dd>
<dt>
<code>time_microseconds: u64</code>
</dt>
<dd>
 On-chain time during  he block at the given height
</dd>
</dl>


</details>

<a name="@Constants_0"></a>

## Constants


<a name="0x1_Block_EBLOCK_METADATA"></a>

The <code><a href="Block.md#0x1_Block_BlockMetadata">BlockMetadata</a></code> resource is in an invalid state


<pre><code><b>const</b> <a href="Block.md#0x1_Block_EBLOCK_METADATA">EBLOCK_METADATA</a>: u64 = 0;
</code></pre>



<a name="0x1_Block_EVM_OR_VALIDATOR"></a>

An invalid signer was provided. Expected the signer to be the VM or a Validator.


<pre><code><b>const</b> <a href="Block.md#0x1_Block_EVM_OR_VALIDATOR">EVM_OR_VALIDATOR</a>: u64 = 1;
</code></pre>



<a name="0x1_Block_initialize_block_metadata"></a>

## Function `initialize_block_metadata`

This can only be invoked by the Association address, and only a single time.
Currently, it is invoked in the genesis transaction


<pre><code><b>public</b> <b>fun</b> <a href="Block.md#0x1_Block_initialize_block_metadata">initialize_block_metadata</a>(account: &signer)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Block.md#0x1_Block_initialize_block_metadata">initialize_block_metadata</a>(account: &signer) {
    <a href="Timestamp.md#0x1_Timestamp_assert_genesis">Timestamp::assert_genesis</a>();
    // Operational constraint, only callable by the Association <b>address</b>
    <a href="CoreAddresses.md#0x1_CoreAddresses_assert_diem_root">CoreAddresses::assert_diem_root</a>(account);

    <b>assert</b>!(!<a href="Block.md#0x1_Block_is_initialized">is_initialized</a>(), <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Errors.md#0x1_Errors_already_published">Errors::already_published</a>(<a href="Block.md#0x1_Block_EBLOCK_METADATA">EBLOCK_METADATA</a>));
    <b>move_to</b>&lt;<a href="Block.md#0x1_Block_BlockMetadata">BlockMetadata</a>&gt;(
        account,
        <a href="Block.md#0x1_Block_BlockMetadata">BlockMetadata</a> {
            height: 0,
            new_block_events: <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Event.md#0x1_Event_new_event_handle">Event::new_event_handle</a>&lt;<a href="Block.md#0x1_Block_NewBlockEvent">Self::NewBlockEvent</a>&gt;(account),
        }
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Timestamp.md#0x1_Timestamp_AbortsIfNotGenesis">Timestamp::AbortsIfNotGenesis</a>;
<b>include</b> <a href="CoreAddresses.md#0x1_CoreAddresses_AbortsIfNotDiemRoot">CoreAddresses::AbortsIfNotDiemRoot</a>;
<b>aborts_if</b> <a href="Block.md#0x1_Block_is_initialized">is_initialized</a>() <b>with</b> Errors::ALREADY_PUBLISHED;
<b>ensures</b> <a href="Block.md#0x1_Block_is_initialized">is_initialized</a>();
<b>ensures</b> <a href="Block.md#0x1_Block_get_current_block_height">get_current_block_height</a>() == 0;
</code></pre>



</details>

<a name="0x1_Block_is_initialized"></a>

## Function `is_initialized`

Helper function to determine whether this module has been initialized.


<pre><code><b>fun</b> <a href="Block.md#0x1_Block_is_initialized">is_initialized</a>(): bool
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="Block.md#0x1_Block_is_initialized">is_initialized</a>(): bool {
    <b>exists</b>&lt;<a href="Block.md#0x1_Block_BlockMetadata">BlockMetadata</a>&gt;(@DiemRoot)
}
</code></pre>



</details>

<a name="0x1_Block_block_prologue"></a>

## Function `block_prologue`

Set the metadata for the current block.
The runtime always runs this before executing the transactions in a block.


<pre><code><b>fun</b> <a href="Block.md#0x1_Block_block_prologue">block_prologue</a>(vm: signer, round: u64, timestamp: u64, previous_block_votes: vector&lt;<b>address</b>&gt;, proposer: <b>address</b>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="Block.md#0x1_Block_block_prologue">block_prologue</a>(
    vm: signer,
    round: u64,
    timestamp: u64,
    previous_block_votes: vector&lt;<b>address</b>&gt;,
    proposer: <b>address</b>
) <b>acquires</b> <a href="Block.md#0x1_Block_BlockMetadata">BlockMetadata</a> {
    <a href="Timestamp.md#0x1_Timestamp_assert_operating">Timestamp::assert_operating</a>();
    // Operational constraint: can only be invoked by the VM.
    <a href="CoreAddresses.md#0x1_CoreAddresses_assert_vm">CoreAddresses::assert_vm</a>(&vm);

    // Authorization
    <b>assert</b>!(
        proposer == @VMReserved || <a href="ValidatorSystem.md#0x1_ValidatorSystem_is_validator">ValidatorSystem::is_validator</a>(proposer),
        <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Errors.md#0x1_Errors_requires_address">Errors::requires_address</a>(<a href="Block.md#0x1_Block_EVM_OR_VALIDATOR">EVM_OR_VALIDATOR</a>)
    );

    <b>let</b> block_metadata_ref = <b>borrow_global_mut</b>&lt;<a href="Block.md#0x1_Block_BlockMetadata">BlockMetadata</a>&gt;(@DiemRoot);
    <a href="Timestamp.md#0x1_Timestamp_update_global_time">Timestamp::update_global_time</a>(&vm, proposer, timestamp);
    block_metadata_ref.height = block_metadata_ref.height + 1;
    <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Event.md#0x1_Event_emit_event">Event::emit_event</a>&lt;<a href="Block.md#0x1_Block_NewBlockEvent">NewBlockEvent</a>&gt;(
        &<b>mut</b> block_metadata_ref.new_block_events,
        <a href="Block.md#0x1_Block_NewBlockEvent">NewBlockEvent</a> {
            round,
            proposer,
            previous_block_votes,
            time_microseconds: timestamp,
        }
    );
}
</code></pre>



</details>

<details>
<summary>Specification</summary>



<pre><code><b>include</b> <a href="Timestamp.md#0x1_Timestamp_AbortsIfNotOperating">Timestamp::AbortsIfNotOperating</a>;
<b>include</b> <a href="CoreAddresses.md#0x1_CoreAddresses_AbortsIfNotVM">CoreAddresses::AbortsIfNotVM</a>{account: vm};
<b>aborts_if</b> proposer != @VMReserved && !<a href="ValidatorSystem.md#0x1_ValidatorSystem_spec_is_validator">ValidatorSystem::spec_is_validator</a>(proposer)
    <b>with</b> Errors::REQUIRES_ADDRESS;
<b>ensures</b> <a href="Timestamp.md#0x1_Timestamp_spec_now_microseconds">Timestamp::spec_now_microseconds</a>() == timestamp;
<b>ensures</b> <a href="Block.md#0x1_Block_get_current_block_height">get_current_block_height</a>() == <b>old</b>(<a href="Block.md#0x1_Block_get_current_block_height">get_current_block_height</a>()) + 1;
<b>aborts_if</b> <a href="Block.md#0x1_Block_get_current_block_height">get_current_block_height</a>() + 1 &gt; MAX_U64 <b>with</b> EXECUTION_FAILURE;
<b>include</b> <a href="Block.md#0x1_Block_BlockPrologueEmits">BlockPrologueEmits</a>;
</code></pre>




<a name="0x1_Block_BlockPrologueEmits"></a>


<pre><code><b>schema</b> <a href="Block.md#0x1_Block_BlockPrologueEmits">BlockPrologueEmits</a> {
    round: u64;
    timestamp: u64;
    previous_block_votes: vector&lt;<b>address</b>&gt;;
    proposer: <b>address</b>;
    <b>let</b> handle = <b>global</b>&lt;<a href="Block.md#0x1_Block_BlockMetadata">BlockMetadata</a>&gt;(@DiemRoot).new_block_events;
    <b>let</b> msg = <a href="Block.md#0x1_Block_NewBlockEvent">NewBlockEvent</a> {
        round,
        proposer,
        previous_block_votes,
        time_microseconds: timestamp,
    };
    <b>emits</b> msg <b>to</b> handle;
}
</code></pre>



</details>

<a name="0x1_Block_get_current_block_height"></a>

## Function `get_current_block_height`

Get the current block height


<pre><code><b>public</b> <b>fun</b> <a href="Block.md#0x1_Block_get_current_block_height">get_current_block_height</a>(): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="Block.md#0x1_Block_get_current_block_height">get_current_block_height</a>(): u64 <b>acquires</b> <a href="Block.md#0x1_Block_BlockMetadata">BlockMetadata</a> {
    <b>assert</b>!(<a href="Block.md#0x1_Block_is_initialized">is_initialized</a>(), <a href="../../../../../../../DPN/releases/artifacts/current/build/MoveStdlib/docs/Errors.md#0x1_Errors_not_published">Errors::not_published</a>(<a href="Block.md#0x1_Block_EBLOCK_METADATA">EBLOCK_METADATA</a>));
    <b>borrow_global</b>&lt;<a href="Block.md#0x1_Block_BlockMetadata">BlockMetadata</a>&gt;(@DiemRoot).height
}
</code></pre>



</details>

<a name="@Module_Specification_1"></a>

## Module Specification



<a name="@Initialization_2"></a>

### Initialization

This implies that <code><a href="Block.md#0x1_Block_BlockMetadata">BlockMetadata</a></code> is published after initialization and stays published
ever after


<pre><code><b>invariant</b> [suspendable] <a href="Timestamp.md#0x1_Timestamp_is_operating">Timestamp::is_operating</a>() ==&gt; <a href="Block.md#0x1_Block_is_initialized">is_initialized</a>();
</code></pre>
